using UnityAuthCore.Backends;
using UnityAuthCore.Core;
using UnityAuthCore.Engine;
using UnityAuthCore.Http;
using UnityAuthCore.Multiplayer;
using UnityAuthCore.Security;
using UnityEngine;

namespace UnityAuthCore.Config
{
    /// <summary>
    /// Selects how a dedicated server or host verifies client access tokens during multiplayer connection approval.
    /// </summary>
    public enum ServerValidationMode
    {
        /// <summary>Verifies HS256 JWT signatures locally using a shared secret with zero network hops.</summary>
        LocalHs256Secret = 0,
        /// <summary>Validates tokens by calling the backend's introspection endpoint via <see cref="IAuthBackendAdapter.IntrospectTokenAsync"/>.</summary>
        RemoteIntrospection = 1
    }

    /// <summary>
    /// Designer and DevOps-configurable framework settings asset.
    /// Supports in-process Mock mode, any REST/Docker backend via <see cref="RestEndpointMap"/>, or custom <see cref="IAuthBackendAdapter"/> injection.
    /// </summary>
    [CreateAssetMenu(fileName = "AuthFrameworkConfig", menuName = "UnityAuthCore/Auth Framework Config", order = 100)]
    public class AuthFrameworkConfig : ScriptableObject
    {
        /// <summary>Active backend mode determining whether to wire <see cref="MockAuthTransport"/>, REST endpoints, or a custom adapter.</summary>
        [Header("Backend Mode")]
        public AuthBackendMode backendMode = AuthBackendMode.MockInProcess;
        /// <summary>Base URL of the authentication REST server (used when <see cref="backendMode"/> is <see cref="AuthBackendMode.RestEndpoint"/>).</summary>
        public string baseUrl = "http://localhost:8080";
        /// <summary>Optional public client API key attached as an <c>X-Api-Key</c> header on REST requests.</summary>
        public string clientApiKey = string.Empty;
        /// <summary>Endpoint path overrides used by <see cref="RestAuthBackendAdapter"/>.</summary>
        public RestEndpointMap restEndpoints = new RestEndpointMap();

        /// <summary>Persistence strategy created by <see cref="CreateTokenStore"/>.</summary>
        [Header("Session & Retry Policy")]
        public TokenStorageMode tokenStorage = TokenStorageMode.EncryptedFile;
        /// <summary>File name under <see cref="Application.persistentDataPath"/> when using <see cref="TokenStorageMode.EncryptedFile"/>.</summary>
        public string customStorageFileName = "unity_auth_core_session.dat";
        /// <summary>Lead time in seconds before access token expiry when <see cref="AuthClient"/> proactively refreshes the session.</summary>
        [Min(0)] public int proactiveRefreshSkewSeconds = 30;
        /// <summary>Maximum number of retry attempts performed by <see cref="ExponentialBackoffRetryPolicy"/> for transient errors.</summary>
        [Min(0)] public int maxRetries = 2;
        /// <summary>Initial exponential backoff delay in milliseconds before jitter.</summary>
        [Min(50)] public int retryBaseDelayMs = 200;

        /// <summary>Token verification mode used by <see cref="CreateServerTokenValidator"/>.</summary>
        [Header("Dedicated Multiplayer Server Validation")]
        public ServerValidationMode serverValidationMode = ServerValidationMode.LocalHs256Secret;
        /// <summary>Shared HS256 signing secret for <see cref="LocalHs256JwtValidator"/> (server builds or local dev only).</summary>
        [Tooltip("Only populate on dedicated server builds or local dev tests; never embed production signing secrets in shipped game clients.")]
        public string serverHs256Secret = "dev-local-mock-secret-change-in-production-32bytes";
        /// <summary>Expected JWT <c>iss</c> claim checked during local HS256 verification.</summary>
        public string expectedIssuer = "unity-auth-core-mock";
        /// <summary>Expected JWT <c>aud</c> claim checked during local HS256 verification.</summary>
        public string expectedAudience = "unity-game-client";
        /// <summary>Optional privileged server key sent via <c>X-Server-Key</c> when using <see cref="RemoteIntrospectionValidator"/>.</summary>
        public string serverIntrospectionApiKey = string.Empty;

        /// <summary>
        /// Instantiates an <see cref="ITokenStore"/> matching <see cref="tokenStorage"/> and <see cref="customStorageFileName"/>.
        /// </summary>
        /// <returns>An <see cref="EncryptedFileTokenStore"/> or <see cref="InMemoryTokenStore"/> instance.</returns>
        public ITokenStore CreateTokenStore()
        {
            if (tokenStorage == TokenStorageMode.EncryptedFile)
            {
                string path = string.IsNullOrWhiteSpace(customStorageFileName)
                    ? null
                    : System.IO.Path.Combine(Application.persistentDataPath, customStorageFileName);
                return new EncryptedFileTokenStore(path);
            }
            return new InMemoryTokenStore();
        }

        /// <summary>
        /// Builds a fully wired <see cref="AuthClient"/> using this asset's settings and optional overrides.
        /// </summary>
        /// <param name="customAdapter">Optional custom <see cref="IAuthBackendAdapter"/>; defaults to <see cref="RestAuthBackendAdapter"/>.</param>
        /// <param name="customTransport">Optional custom <see cref="IHttpTransport"/>; defaults to <see cref="MockAuthTransport"/> in mock mode or <see cref="UnityWebRequestTransport"/> otherwise.</param>
        /// <param name="customStore">Optional custom <see cref="ITokenStore"/>; defaults to <see cref="CreateTokenStore"/>.</param>
        /// <returns>A configured <see cref="AuthClient"/> ready for authentication calls.</returns>
        public AuthClient CreateClient(IAuthBackendAdapter customAdapter = null, IHttpTransport customTransport = null, ITokenStore customStore = null)
        {
            var retry = new ExponentialBackoffRetryPolicy(maxRetries, retryBaseDelayMs);
            IHttpTransport transport = customTransport ?? (backendMode == AuthBackendMode.MockInProcess
                ? (IHttpTransport)new MockAuthTransport()
                : new UnityWebRequestTransport());

            var http = new ApiHttpClient(transport, retry);

            IAuthBackendAdapter adapter = customAdapter;
            if (adapter == null)
            {
                string url = backendMode == AuthBackendMode.MockInProcess ? "http://mock.local" : baseUrl;
                adapter = new RestAuthBackendAdapter(http, url, restEndpoints, clientApiKey);
            }

            ITokenStore store = customStore ?? CreateTokenStore();
            return new AuthClient(adapter, http, store, proactiveRefreshSkewSeconds);
        }

        /// <summary>
        /// Creates an <see cref="IServerTokenValidator"/> based on <see cref="serverValidationMode"/>.
        /// Falls back to <see cref="LocalHs256JwtValidator"/> when remote introspection is selected without an adapter.
        /// </summary>
        /// <param name="introspectionAdapter">Adapter used for <see cref="ServerValidationMode.RemoteIntrospection"/>.</param>
        /// <returns>A configured <see cref="IServerTokenValidator"/> for multiplayer connection approval.</returns>
        public IServerTokenValidator CreateServerTokenValidator(IAuthBackendAdapter introspectionAdapter = null)
        {
            if (serverValidationMode == ServerValidationMode.RemoteIntrospection && introspectionAdapter != null)
            {
                return new RemoteIntrospectionValidator(introspectionAdapter, serverIntrospectionApiKey);
            }

            return new LocalHs256JwtValidator(serverHs256Secret, expectedIssuer, expectedAudience);
        }
    }
}
