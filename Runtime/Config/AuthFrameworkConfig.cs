using UnityAuthCore.Backends;
using UnityAuthCore.Core;
using UnityAuthCore.Engine;
using UnityAuthCore.Http;
using UnityAuthCore.Multiplayer;
using UnityAuthCore.Security;
using UnityEngine;

namespace UnityAuthCore.Config
{
    public enum ServerValidationMode
    {
        LocalHs256Secret = 0,
        RemoteIntrospection = 1
    }

    /// <summary>
    /// Designer and DevOps-configurable framework settings asset.
    /// Supports in-process Mock mode, any REST/Docker backend via RestEndpointMap, or custom IAuthBackendAdapter injection.
    /// </summary>
    [CreateAssetMenu(fileName = "AuthFrameworkConfig", menuName = "UnityAuthCore/Auth Framework Config", order = 100)]
    public class AuthFrameworkConfig : ScriptableObject
    {
        [Header("Backend Mode")]
        public AuthBackendMode backendMode = AuthBackendMode.MockInProcess;
        public string baseUrl = "http://localhost:8080";
        public string clientApiKey = string.Empty;
        public RestEndpointMap restEndpoints = new RestEndpointMap();

        [Header("Session & Retry Policy")]
        public TokenStorageMode tokenStorage = TokenStorageMode.EncryptedFile;
        public string customStorageFileName = "unity_auth_core_session.dat";
        [Min(0)] public int proactiveRefreshSkewSeconds = 30;
        [Min(0)] public int maxRetries = 2;
        [Min(50)] public int retryBaseDelayMs = 200;

        [Header("Dedicated Multiplayer Server Validation")]
        public ServerValidationMode serverValidationMode = ServerValidationMode.LocalHs256Secret;
        [Tooltip("Only populate on dedicated server builds or local dev tests; never embed production signing secrets in shipped game clients.")]
        public string serverHs256Secret = "dev-local-mock-secret-change-in-production-32bytes";
        public string expectedIssuer = "unity-auth-core-mock";
        public string expectedAudience = "unity-game-client";
        public string serverIntrospectionApiKey = string.Empty;

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
