# UnityAuthCore

Backend-agnostic authentication, account lifecycle, and typed REST API framework for Unity 6.

UnityAuthCore separates HTTP transport, auth backend adapters, encrypted token storage, and Unity Multiplayer connection approval so teams can plug in any self-hosted server or BaaS (Supabase, Firebase, PlayFab, Steam, or custom APIs) without locking gameplay or UI code to one vendor.

## Features

- **Backend-agnostic adapter architecture (`IAuthBackendAdapter`):** Ship your own backend or BaaS adapter without modifying game UI or session logic. Includes `RestAuthBackendAdapter` with a customizable `RestEndpointMap`, an in-process `MockAuthTransport` for instant testing, and starter adapters for Supabase and Firebase under `Samples~/BackendAdapters/`.
- **Typed REST client (`ApiHttpClient`):** Async `UnityWebRequest` pipeline with `ApiResponse` and structured `ApiError` envelopes, `IApiInterceptor` middleware (`BearerAuthInterceptor`, `RequestIdInterceptor`), exponential backoff + jitter retry policy (`429` / `5xx` with `Retry-After` support), and live HTTP request tracing.
- **Single-flight `401` token refresh:** When multiple concurrent API calls fail with `401 Unauthorized`, `ApiHttpClient` coalesces them into a single refresh request and automatically replays all pending calls with the rotated access token.
- **JWT utilities and encrypted token storage:** Built-in Base64Url decoding, claims inspection, HS256 signing and constant-time verification (`JwtUtility`), plus `InMemoryTokenStore` and `EncryptedFileTokenStore` (AES-256-CBC with Encrypt-then-MAC HMAC-SHA256 tamper rejection).
- **Unity Multiplayer connection approval (`MultiplayerAuthBridge`):** Transport-agnostic UTF-8 `MultiplayerAuthTicket` serialization for Netcode for GameObjects (`ConnectionData`), Mirror, and FishNet, paired with dedicated-server validators (`LocalHs256JwtValidator` and `RemoteIntrospectionValidator`) and an active `clientId` to `accountId` registry with duplicate-login control.
- **Optional Dockerized reference server and OpenAPI 3.0 contract:** Includes `Docs~/openapi.yaml` and a self-contained Node.js 22 LTS Docker backend under `Server~/` (`Dockerfile`, `docker-compose.yml`, `scrypt` password hashing, rotating refresh tokens with reuse-detection family revocation, rate limiting, and `/v1/auth/introspect`).
- **UI Toolkit Auth & API Console (`Tools > UnityAuthCore > Auth & API Console`):** Four-tab Editor workbench for running auth flows, inspecting decoded JWT claims, testing single-flight `401` refresh across concurrent requests, verifying multiplayer handshake tickets, and inspecting live HTTP traces.
- **Canvas and Scene wiring (`AccountController`):** Drop-in `MonoBehaviour` with Inspector-bindable `UnityEvent` hooks (`onSignedIn`, `onSignedOut`, `onSessionRefreshed`, `onProfileUpdated`, `onAuthError`, `onBusyStateChanged`) and custom adapter injection.

## Requirements

- Unity `6000.0` or newer
- Optional for the self-hosted reference backend in `Server~/`: Docker (or Node.js 22+)

## Installation

### Unity Package Manager (Git URL)

1. Open **Window > Package Manager**.
2. Click **+** and choose **Install package from git URL...**.
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

### 1. Test in the Editor console

Open **Tools > UnityAuthCore > Auth & API Console**. In the default **MockInProcess** mode you can sign in as a guest, upgrade to email/password, inspect decoded HS256 JWT claims, force-expire the access token while firing 3 concurrent requests, and verify multiplayer tickets immediately.

### 2. Deploy the optional Docker backend (or bring your own)

```bash
cd Plugins/UnityAuthCore/Server~
cp .env.example .env
docker compose up --build -d
```

Create a config asset with **Create > UnityAuthCore > Auth Framework Config**, set `backendMode` to `RestEndpoint`, and point `baseUrl` at `http://localhost:8080` (or your own server implementing [Docs~/openapi.yaml](Docs~/openapi.yaml)).

### 3. Plug in any custom backend or BaaS

Implement `IAuthBackendAdapter` (see `Samples~/BackendAdapters/SampleSupabaseAuthAdapter.cs` and `SampleFirebaseAuthAdapter.cs`) and pass it to `AuthClient` or `AccountController`:

```csharp
using UnityAuthCore.Components;
using UnityAuthCore.Core;
using UnityEngine;

public class AuthBootstrap : MonoBehaviour
{
    [SerializeField] private AccountController accountController;

    private void Awake()
    {
        IAuthBackendAdapter myBackend = CreateCustomAdapter();
        accountController.ConfigureCustomAdapter(myBackend);
    }

    private IAuthBackendAdapter CreateCustomAdapter()
    {
        // Return your Supabase, Firebase, PlayFab, Steam, or custom REST adapter
        return null;
    }
}
```

### 4. Authenticate Unity Multiplayer connections

On the client, attach the signed ticket payload before connecting:

```csharp
byte[] payload = accountController.BuildMultiplayerConnectionPayload();
// NGO: NetworkManager.Singleton.NetworkConfig.ConnectionData = payload;
```

On the Dedicated Server or Host, validate the payload during connection approval:

```csharp
IServerTokenValidator validator = config.CreateServerTokenValidator(introspectionAdapter);
MultiplayerApprovalResult approval = await bridge.ApproveConnectionAsync(clientId, payload, validator);
if (approval.Approved)
{
    Debug.Log($"Player verified: {approval.Identity.accountId}");
}
```

## Extension contracts

| Interface | Purpose | Default implementation |
| :--- | :--- | :--- |
| `IAuthBackendAdapter` | Translates auth and profile operations to any self-hosted API or BaaS | `RestAuthBackendAdapter` (plus Supabase/Firebase starters in `Samples~/`) |
| `IHttpTransport` | Sends raw HTTP requests and returns status, headers, and body | `UnityWebRequestTransport`, `MockAuthTransport` |
| `IApiInterceptor` | Modifies outgoing requests or inspects incoming responses | `BearerAuthInterceptor`, `RequestIdInterceptor` |
| `IRetryPolicy` | Controls retry attempts and backoff delays for transient failures | `ExponentialBackoffRetryPolicy` |
| `ITokenStore` | Persists and loads `AuthSession` securely across app restarts | `InMemoryTokenStore`, `EncryptedFileTokenStore` |
| `IServerTokenValidator` | Verifies client access tokens on a Dedicated Server or Host | `LocalHs256JwtValidator`, `RemoteIntrospectionValidator` |

## Testing

The package includes EditMode NUnit tests in `Tests/Editor/UnityAuthCoreTests.cs` covering:

- Guest sign-in, guest-to-email account upgrade, and profile updates
- Email registration, duplicate conflict (`409`), login, and invalid credentials (`401`)
- Single-flight `401` token refresh across 3 concurrent API calls (asserts refresh fires once)
- Refresh token rotation and reuse-detection session family revocation
- `JwtUtility` HS256 signing, claims parsing, signature tamper rejection, and expiry validation
- `EncryptedFileTokenStore` round-trip persistence and HMAC tamper rejection
- `MultiplayerAuthBridge` ticket encoding, Local HS256 and Remote Introspection validation, and duplicate-login handling
- `ExponentialBackoffRetryPolicy` transient `429` retry recovery
- Custom `IAuthBackendAdapter` injection and `AccountController` `UnityEvent` lifecycle

## License

MIT. See [LICENSE.md](LICENSE.md).
