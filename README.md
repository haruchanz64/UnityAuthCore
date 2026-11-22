# UnityAuthCore

Backend-agnostic authentication, account lifecycle, and typed REST API framework for Unity 6. It separates HTTP transport, auth backend adapters, encrypted token storage, and Unity Multiplayer connection approval so teams can connect to a self-hosted server or BaaS (Supabase, Firebase, PlayFab, Steam, or custom APIs) without coupling gameplay or UI code to one vendor.

## Features

- **Backend-agnostic adapter architecture (`IAuthBackendAdapter`):** Swap self-hosted servers or BaaS providers without changing UI or session code. Ships with `RestAuthBackendAdapter` and a customizable `RestEndpointMap`, an in-process `MockAuthTransport` for offline Editor and test workflows, and starter adapters for Supabase and Firebase under `Samples~/BackendAdapters/`.
- **Typed REST client (`ApiHttpClient`):** Async `UnityWebRequest` pipeline with `AuthResult<T>` and structured `ApiError` envelopes, ordered `IApiInterceptor` middleware (`RequestIdInterceptor`, `BearerAuthInterceptor`), bounded exponential backoff with jitter (`ExponentialBackoffRetryPolicy` handling network errors, `408`, `429` with `Retry-After`, and `5xx`), and an in-memory HTTP trace ring buffer with password redaction.
- **Single-flight `401` token refresh:** When multiple concurrent authenticated requests fail with `401 Unauthorized`, `ApiHttpClient` coalesces them onto a single refresh call via `OnUnauthorizedRefreshAsync` and replays every waiting request using the rotated access token.
- **Pure C# JWT utilities and encrypted token storage:** Includes RFC 7515 Base64Url helpers, claims decoding, HS256 signing, and constant-time HS256 verification (`JwtUtility`), plus `InMemoryTokenStore` and `EncryptedFileTokenStore` (AES-256-CBC with Encrypt-then-MAC HMAC-SHA256 tamper rejection).
- **Unity Multiplayer connection approval (`MultiplayerAuthBridge`):** Transport-agnostic UTF-8 `MultiplayerAuthTicket` serialization compatible with Netcode for GameObjects (`ConnectionData`), Mirror, and FishNet, paired with dedicated-server validators (`LocalHs256JwtValidator`, `RemoteIntrospectionValidator`), optional client version enforcement, and an active `clientId` to `accountId` registry with duplicate-login control.
- **Scene and Canvas component (`AccountController`):** Drop-in `MonoBehaviour` exposing Inspector-bindable `UnityEvent` hooks (`onSignedIn`, `onSignedOut`, `onSessionRefreshed`, `onProfileUpdated`, `onAuthError`, `onBusyStateChanged`), zero-argument button helpers (`SignInAsGuest`, `SignOut`), and runtime custom adapter injection.
- **UI Toolkit console and inspector:** Four-tab `AuthWorkbenchWindow` (**Tools > HaruChanZ64 > Networking > UnityAuthCore > Auth and API Console**) for testing auth flows, inspecting decoded JWT claims, triggering 3-way concurrent `401` refresh tests, verifying multiplayer tickets, and reviewing live HTTP traces, plus a custom `AuthFrameworkConfigInspector`.
- **Optional Dockerized reference server and OpenAPI 3.0 contract:** Ships [Docs~/openapi.yaml](Docs~/openapi.yaml) alongside a self-contained Node.js 22 LTS reference backend in [Server~/](Server~/README.md) (`scrypt` salted password hashing, rotating refresh tokens with reuse-detection family revocation, per-IP rate limiting, and `/v1/auth/introspect`).

## Requirements

- Unity `6000.0` or newer
- Zero required external Unity package dependencies
- Optional for the self-hosted reference backend in `Server~/`: Docker or Node.js `22+`
- Optional for multiplayer networking integration: Netcode for GameObjects, Mirror, or FishNet (not required to compile `UnityAuthCore.Runtime`)

## Installation

### Unity Package Manager (Git URL)

1. Open **Window > Package Manager** in Unity 6 (`6000.0+`).
2. Click **+** (top-left) and choose **Install package from git URL...**.
3. Enter:

```text
https://github.com/haruchanz64/UnityAuthCore.git
```

### Local package

Add the package path to `Packages/manifest.json`:

```json
{
  "dependencies": {
    "com.haruchanz64.unity-auth-core": "file:../Plugins/UnityAuthCore"
  }
}
```

## Quick start

1. Open **Tools > HaruChanZ64 > Networking > UnityAuthCore > Auth and API Console**. In the default **MockInProcess** sandbox mode you can sign in as a guest, register or log in with email/password, upgrade a guest account, inspect decoded HS256 JWT claims, run the 3-request single-flight `401` refresh test, and verify multiplayer handshake tickets with no external server.
2. Create a configuration asset via **Assets > Create > UnityAuthCore > Auth Framework Config**. Choose `backendMode` (`MockInProcess`, `RestEndpoint`, or `CustomAdapter`), set `tokenStorage` (`EncryptedFile` or `InMemory`), and configure retry and refresh skew values.
3. *(Optional)* Start the Dockerized reference backend in `Server~/` when testing against a live HTTP server:

```bash
cd Plugins/UnityAuthCore/Server~
cp .env.example .env
docker compose up --build -d
```

Set `backendMode` to `RestEndpoint`, point `baseUrl` at `http://localhost:8080`, and align `expectedIssuer`, `expectedAudience`, and `serverHs256Secret` on your server-side config asset with `Server~/.env`.
4. Add `AccountController` (from `UnityAuthCore.Components`) to a bootstrap GameObject, assign your `AuthFrameworkConfig` asset, and bind `onSignedIn`, `onSignedOut`, `onAuthError`, and `onBusyStateChanged` in the Inspector.
5. Click **Open in Auth & API Console** in the `AuthFrameworkConfig` Inspector to test directly against that asset's settings.

## Core concepts

### Request pipeline and single-flight `401` refresh

Every request sent through `ApiHttpClient.SendRawAsync` or `SendJsonAsync<T>` runs through a deterministic loop:

1. **Before-send interceptors:** Runs registered `IApiInterceptor.OnBeforeSendAsync` hooks in registration order. `ApiHttpClient` automatically registers `RequestIdInterceptor` (`X-Request-Id`), and `AuthClient` adds `BearerAuthInterceptor` to attach `Authorization: Bearer <token>` on requests where `ApiRequest.RequiresAuth` is true.
2. **Transport dispatch and after-receive hooks:** Sends the request via `IHttpTransport` (`UnityWebRequestTransport` in live mode or `MockAuthTransport` in mock mode), runs `OnAfterReceiveAsync` in reverse registration order, and records a bounded `ApiTraceEntry` (redacting any JSON body containing `"password"`).
3. **Single-flight `401` recovery:** If a protected request returns HTTP `401` on its first attempt and `OnUnauthorizedRefreshAsync` is assigned, `ApiHttpClient` locks around a shared `_inFlightRefreshTask` so all concurrent `401` callers await the same refresh request. When refresh succeeds, each request loops and re-runs `BearerAuthInterceptor` to pick up the new access token.
4. **Transient retry policy:** For non-auth transient failures (`IsNetworkError`, `408`, `429`, `5xx`), `ExponentialBackoffRetryPolicy` honors numeric `Retry-After` headers or computes bounded exponential backoff with random jitter. Refresh and logout requests set `ApiRequest.SkipRetry = true` so rotating refresh tokens are never replayed automatically.

### Session lifecycle and encrypted token storage

`AuthClient` coordinates `IAuthBackendAdapter`, `ApiHttpClient`, and `ITokenStore`. Calling `InitializeAsync()` loads any persisted `AuthSession` from `ITokenStore` and refreshes it automatically if it is within `refreshSkewSeconds` of expiry. Protected calls (`GetProfileAsync`, `UpdateProfileAsync`, `UpgradeGuestWithEmailAsync`) also run a proactive expiry check before hitting the network.

When `TokenStorageMode.EncryptedFile` is selected, `EncryptedFileTokenStore` writes `[32-byte HMAC-SHA256][16-byte random IV][AES-256-CBC ciphertext]` to `Application.persistentDataPath`. On load, the HMAC tag is verified in constant time before decryption; modified or truncated files return `null`.

### Multiplayer connection approval

`MultiplayerAuthBridge` decouples account authentication from your chosen networking library:

- **Client side:** `MultiplayerAuthBridge.BuildClientConnectionPayload(session, clientVersion)` (or `accountController.BuildMultiplayerConnectionPayload()`) encodes a `MultiplayerAuthTicket` (`accessToken`, `clientVersion`, `nonce`, `issuedAtUnixSeconds`) as UTF-8 JSON bytes ready for NGO `ConnectionData`, Mirror, or FishNet handshakes.
- **Server side:** `ApproveConnectionAsync(clientId, payload, validator)` validates the payload structure, checks `RequiredClientVersion` if configured, verifies the token using either `LocalHs256JwtValidator` (offline constant-time HS256 check) or `RemoteIntrospectionValidator` (`POST /v1/auth/introspect` or BaaS lookup), enforces `RejectDuplicateAccountLogin` (or reports `DisplacedPreviousClientId`), and stores the `MultiplayerVerifiedIdentity` until `HandleClientDisconnected(clientId)` is called.

## Code examples

### 1. Wire `AccountController` with a custom `IAuthBackendAdapter`

Inject any BaaS or custom backend adapter before signing in, while keeping UI scenes bound to `AccountController`:

```csharp
using UnityAuthCore.Components;
using UnityAuthCore.Core;
using UnityAuthCore.Http;
using UnityAuthCore.Samples.Backends;
using UnityEngine;

public sealed class AuthBootstrap : MonoBehaviour
{
    [SerializeField] private AccountController accountController;
    [SerializeField] private string supabaseUrl = "https://your-project.supabase.co";
    [SerializeField] private string supabaseAnonKey = "your-publishable-key";

    private void Awake()
    {
        var http = new ApiHttpClient(new UnityWebRequestTransport());
        IAuthBackendAdapter adapter = new SampleSupabaseAuthAdapter(http, supabaseUrl, supabaseAnonKey);
        accountController.ConfigureCustomAdapter(adapter);
    }

    public async void LoginPlayer(string email, string password)
    {
        AuthResult<AuthSession> result = await accountController.LoginAsync(email, password);
        if (!result.Succeeded)
        {
            Debug.LogWarning($"Login failed [{result.Error.errorCode}]: {result.Error.message}");
            return;
        }

        Debug.Log($"Signed in as {result.Data.user.displayName} ({result.Data.user.accountId})");
    }
}
```

### 2. Add a custom `IApiInterceptor` and send typed requests

Attach custom headers, telemetry, or request signing through `IApiInterceptor`, and reuse `AuthClient.HttpClient` for authenticated game API calls that automatically benefit from single-flight `401` refresh:

```csharp
using System;
using System.Threading;
using System.Threading.Tasks;
using UnityAuthCore.Core;
using UnityAuthCore.Engine;
using UnityEngine;

public sealed class ClientVersionInterceptor : IApiInterceptor
{
    private readonly string _version;

    public ClientVersionInterceptor(string version) => _version = version;

    public Task OnBeforeSendAsync(ApiRequest request, CancellationToken ct = default)
    {
        request.Headers["X-Client-Version"] = _version;
        return Task.CompletedTask;
    }

    public Task OnAfterReceiveAsync(ApiRequest request, HttpRawResponse response, CancellationToken ct = default)
    {
        return Task.CompletedTask;
    }
}

[Serializable]
public sealed class InventoryDto
{
    public int gold;
}

public static class GameApiExample
{
    public static async Task<AuthResult<InventoryDto>> FetchInventoryAsync(AuthClient client, string apiBaseUrl)
    {
        client.HttpClient.AddInterceptor(new ClientVersionInterceptor(Application.version));

        var req = new ApiRequest
        {
            Method = "GET",
            Url = $"{apiBaseUrl.TrimEnd('/')}/v1/inventory",
            RequiresAuth = true
        };

        return await client.HttpClient.SendJsonAsync<InventoryDto>(req);
    }
}
```

### 3. Authenticate Unity Multiplayer connections

Serialize the client ticket before connecting, and verify it on the Dedicated Server or Host during connection approval:

```csharp
using System.Threading.Tasks;
using UnityAuthCore.Components;
using UnityAuthCore.Config;
using UnityAuthCore.Core;
using UnityAuthCore.Multiplayer;
using UnityEngine;

public sealed class MatchServerAuthHandler
{
    private readonly MultiplayerAuthBridge _bridge = new MultiplayerAuthBridge
    {
        RequiredClientVersion = "1.0.0",
        RejectDuplicateAccountLogin = false
    };

    private readonly IServerTokenValidator _validator;

    public MatchServerAuthHandler(AuthFrameworkConfig serverConfig, IAuthBackendAdapter introspectionAdapter = null)
    {
        _validator = serverConfig.CreateServerTokenValidator(introspectionAdapter);
    }

    public static byte[] BuildClientPayload(AccountController controller)
    {
        // Assign to NGO NetworkManager.Singleton.NetworkConfig.ConnectionData before StartClient()
        return controller.BuildMultiplayerConnectionPayload();
    }

    public async Task<MultiplayerApprovalResult> ApproveAsync(ulong clientId, byte[] payload)
    {
        MultiplayerApprovalResult approval = await _bridge.ApproveConnectionAsync(clientId, payload, _validator);
        if (!approval.Approved)
        {
            Debug.LogWarning($"Rejected client {clientId} [{approval.RejectionCode}]: {approval.RejectionReason}");
            return approval;
        }

        if (approval.DisplacedPreviousClientId.HasValue)
        {
            Debug.Log($"Kick previous client {approval.DisplacedPreviousClientId.Value} for duplicate login.");
        }

        Debug.Log($"Approved client {clientId} as {approval.Identity.accountId}");
        return approval;
    }

    public void OnDisconnected(ulong clientId) => _bridge.HandleClientDisconnected(clientId);
}
```

### 4. Inspect JWT claims locally

Decode JWT claims on the client for UI display without exposing a signing secret:

```csharp
using UnityAuthCore.Core;
using UnityAuthCore.Engine;
using UnityEngine;

public static class JwtInspectionExample
{
    public static void LogCurrentClaims(AuthClient client)
    {
        if (client.TryDecodeCurrentClaims(out JwtClaims claims, out string error))
        {
            Debug.Log($"sub={claims.sub}, iss={claims.iss}, exp={claims.exp}, expired={claims.IsExpired()}");
        }
        else
        {
            Debug.LogWarning($"Cannot decode access token: {error}");
        }
    }
}
```

## Extension contracts and core API

| Type | Namespace | Purpose | Built-in implementation |
| :--- | :--- | :--- | :--- |
| `IAuthBackendAdapter` | `UnityAuthCore.Core` | Translates auth, profile, account linking, and introspection operations to any backend | `RestAuthBackendAdapter` (plus Supabase and Firebase starters in `Samples~/`) |
| `IHttpTransport` | `UnityAuthCore.Core` | Dispatches raw `ApiRequest` calls and returns `HttpRawResponse` | `UnityWebRequestTransport`, `MockAuthTransport` |
| `IApiInterceptor` | `UnityAuthCore.Core` | Modifies outgoing requests or inspects incoming responses | `RequestIdInterceptor`, `BearerAuthInterceptor` |
| `IRetryPolicy` | `UnityAuthCore.Core` | Controls retry attempts and backoff delays for transient failures | `ExponentialBackoffRetryPolicy` |
| `ITokenStore` | `UnityAuthCore.Core` | Persists and clears `AuthSession` across app launches | `InMemoryTokenStore`, `EncryptedFileTokenStore` |
| `IServerTokenValidator` | `UnityAuthCore.Core` | Verifies client access tokens on a Dedicated Server or Host | `LocalHs256JwtValidator`, `RemoteIntrospectionValidator` |
| `AuthClient` | `UnityAuthCore.Engine` | High-level session manager coordinating adapter, HTTP client, refresh, and storage | `AuthClient` (including `AuthClient.CreateMock`) |
| `ApiHttpClient` | `UnityAuthCore.Http` | Typed JSON HTTP pipeline with interceptors, retries, traces, and single-flight `401` refresh | `ApiHttpClient` |
| `AccountController` | `UnityAuthCore.Components` | Drop-in `MonoBehaviour` with Inspector `UnityEvent` hooks and custom adapter injection | `AccountController` |
| `AuthFrameworkConfig` | `UnityAuthCore.Config` | ScriptableObject factory configuring backend mode, endpoints, storage, retries, and server validation | `AuthFrameworkConfig` |
| `MultiplayerAuthBridge` | `UnityAuthCore.Multiplayer` | Builds connection tickets, validates handshakes, and tracks active `clientId` to `accountId` mappings | `MultiplayerAuthBridge` |
| `JwtUtility` | `UnityAuthCore.Security` | Pure C# Base64Url encoding, JWT claims decoding, HS256 signing, and constant-time verification | `JwtUtility` |

## Included samples

Import samples from the Package Manager **Samples** tab:

- **Backend Adapters (Supabase, Firebase, Custom)** (`Samples~/BackendAdapters`):
  - `SampleSupabaseAuthAdapter`: Starter `IAuthBackendAdapter` wired to Supabase Auth (GoTrue REST API).
  - `SampleFirebaseAuthAdapter`: Starter `IAuthBackendAdapter` wired to Firebase Identity Toolkit and Secure Token REST APIs.
- **Multiplayer Authenticators (NGO, Mirror, FishNet)** (`Samples~/MultiplayerAdapters`):
  - `SampleMultiplayerAuthWiring`: MonoBehaviour demonstrating `AccountController`, `AuthFrameworkConfig.CreateServerTokenValidator`, and `MultiplayerAuthBridge` connection approval and disconnect cleanup.

The package also includes [Docs~/openapi.yaml](Docs~/openapi.yaml) (OpenAPI 3.0.3 contract) and an optional Dockerized Node.js 22 LTS reference server in [Server~/](Server~/README.md).

## Testing

The package includes EditMode NUnit tests in `Tests/Editor/UnityAuthCoreTests.cs` runnable from **Window > General > Test Runner** (EditMode tab):

- `GuestSignIn_UpgradeToEmail_AndUpdateProfile_WorksEndToEnd`: verifies guest sign-in, guest-to-email upgrade preserving `accountId`, and profile updates.
- `Register_DuplicateEmailReturns409_AndBadPasswordReturns401`: verifies email registration (`201`), duplicate email conflict (`409 EMAIL_ALREADY_EXISTS`), and invalid login credentials (`401 INVALID_CREDENTIALS`).
- `ConcurrentUnauthorizedCalls_TriggerSingleFlightRefreshExactlyOnce`: corrupts the access token across 3 concurrent protected calls and asserts all 3 succeed while `/v1/auth/refresh` is hit once.
- `RefreshTokenReuseDetection_RevokesEntireSessionFamily`: verifies refresh rotation and confirms replaying an already-consumed refresh token revokes the entire token family.
- `JwtUtility_SignsVerifiesAndRejectsTamperedOrExpiredTokens`: verifies HS256 token creation, claims decoding, valid verification, signature tamper rejection (`SIGNATURE_INVALID`), and expiry rejection (`TOKEN_EXPIRED`).
- `EncryptedFileTokenStore_PersistsSessionAndRejectsTamperedFile`: verifies AES-256-CBC round-trip persistence and confirms flipping a byte fails HMAC verification and returns `null`.
- `MultiplayerAuthBridge_ValidatesTicketsViaLocalHs256AndRemoteIntrospect`: verifies ticket encoding, `RequiredClientVersion`, `LocalHs256JwtValidator`, duplicate login rejection (`ACCOUNT_ALREADY_CONNECTED`), disconnect cleanup, and `RemoteIntrospectionValidator`.
- `RetryPolicy_RetriesTransient429AndRecovers`: verifies `ExponentialBackoffRetryPolicy` retries a simulated `429` and succeeds on the second attempt.
- `AccountController_SupportsCustomAdapterInjectionAndFiresUnityEvents`: verifies `ConfigureCustomAdapter`, `UnityEvent` callbacks (`onSignedIn`, `onSignedOut`), and multiplayer payload creation.

## Troubleshooting and limitations

- **`ISSUER_MISMATCH` when switching from Mock mode to the Docker reference server:** `AuthFrameworkConfig.expectedIssuer` defaults to `"unity-auth-core-mock"`, while `Server~/.env.example` defaults `JWT_ISSUER` to `"unity-auth-core-server"`. Match `expectedIssuer`, `expectedAudience`, and `serverHs256Secret` on your server-side `AuthFrameworkConfig` to the values configured in `Server~/.env`.
- **Never ship `serverHs256Secret` in game client builds:** Populate `serverHs256Secret` only in dedicated server builds or local dev tests. For client-hosted or BaaS setups where the host cannot hold a signing secret, use `ServerValidationMode.RemoteIntrospection` with a server-only key or provider token lookup.
- **`JsonUtility` deserialization constraints:** `ApiHttpClient.SendJsonAsync<T>` uses `UnityEngine.JsonUtility`, so response DTOs must be `[Serializable]` classes or structs with public fields (not auto-properties or bare top-level JSON arrays). For arbitrary JSON responses, call `SendJsonAsync<string>` or `SendRawAsync` and parse with your preferred JSON library.
- **`EncryptedFileTokenStore` returns `null` after tampering or device/bundle ID changes:** Any modified or truncated session file fails Encrypt-then-MAC verification and is treated as no saved session. When no custom `passphrase` is passed, the key is derived from `Application.identifier` and `SystemInfo.deviceUniqueIdentifier`, so changing the bundle ID invalidates previously saved files.
- **`AccountController` falls back to Mock mode if unassigned:** If neither `config` nor `ConfigureCustomAdapter(...)` is supplied before `Start()`, `AccountController` creates an in-process `AuthClient.CreateMock(out _)`.
- **Starter BaaS sample stubs:** `SampleFirebaseAuthAdapter` leaves `GetProfileAsync`, `UpdateProfileAsync`, and `LinkEmailPasswordAsync` returning HTTP `501 NOT_IMPLEMENTED`, and `SampleSupabaseAuthAdapter.UpdateProfileAsync` delegates to `GetProfileAsync`. Extend those methods to match your project's profile schema before production use.
- **Reference server persistence:** `Server~/src/server.mjs` stores accounts and refresh tokens in a single JSON file (`data/auth-store.json`) and tracks rate limits in process memory. Replace the storage layer with a database (such as PostgreSQL or Redis) before running multiple server instances in production.

## License

[MIT](LICENSE.md)
