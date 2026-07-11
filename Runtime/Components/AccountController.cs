using System;
using System.Threading.Tasks;
using UnityAuthCore.Config;
using UnityAuthCore.Core;
using UnityAuthCore.Engine;
using UnityAuthCore.Multiplayer;
using UnityEngine;
using UnityEngine.Events;

namespace UnityAuthCore.Components
{
    [Serializable] public sealed class AuthSessionUnityEvent : UnityEvent<AuthSession> { }
    [Serializable] public sealed class AuthProfileUnityEvent : UnityEvent<AuthUserProfile> { }
    [Serializable] public sealed class AuthErrorUnityEvent : UnityEvent<ApiError> { }
    [Serializable] public sealed class AuthBusyUnityEvent : UnityEvent<bool> { }

    /// <summary>
    /// Drop-in MonoBehaviour wiring AuthClient to uGUI Canvas screens, 3D scenes, or multiplayer boot flows.
    /// Supports custom IAuthBackendAdapter injection so developers can plug in any self-hosted or BaaS provider.
    /// </summary>
    [DisallowMultipleComponent]
    public sealed class AccountController : MonoBehaviour
    {
        [Header("Configuration")]
        [SerializeField] private AuthFrameworkConfig config;
        [SerializeField] private bool restoreSessionOnStart = true;
        [SerializeField] private string clientVersion = "1.0.0";

        [Header("Inspector Events (Canvas / Scene / Multiplayer Hooks)")]
        public AuthSessionUnityEvent onSignedIn = new AuthSessionUnityEvent();
        public UnityEvent onSignedOut = new UnityEvent();
        public AuthSessionUnityEvent onSessionRefreshed = new AuthSessionUnityEvent();
        public AuthProfileUnityEvent onProfileUpdated = new AuthProfileUnityEvent();
        public AuthErrorUnityEvent onAuthError = new AuthErrorUnityEvent();
        public AuthBusyUnityEvent onBusyStateChanged = new AuthBusyUnityEvent();

        private AuthClient _client;
        private IAuthBackendAdapter _injectedAdapter;

        public AuthClient Client
        {
            get
            {
                EnsureInitialized();
                return _client;
            }
        }

        public bool IsSignedIn => Client.IsSignedIn;
        public AuthSession CurrentSession => Client.CurrentSession;

        public void ConfigureCustomAdapter(IAuthBackendAdapter customAdapter)
        {
            _injectedAdapter = customAdapter;
            _client = null;
            EnsureInitialized();
        }

        public void SetConfig(AuthFrameworkConfig frameworkConfig)
        {
            config = frameworkConfig;
            _client = null;
            EnsureInitialized();
        }

        private async void Start()
        {
            EnsureInitialized();
            if (restoreSessionOnStart)
            {
                await InitializeSessionAsync();
            }
        }

        public async Task<AuthResult<AuthSession>> InitializeSessionAsync()
        {
            return await RunBusyAsync(() => Client.InitializeAsync());
        }

        public async Task<AuthResult<AuthSession>> SignInGuestAsync(string displayName = null)
        {
            return await RunBusyAsync(() => Client.SignInGuestAsync(SystemInfo.deviceUniqueIdentifier, displayName));
        }

        public async Task<AuthResult<AuthSession>> RegisterAsync(string email, string password, string displayName = null)
        {
            return await RunBusyAsync(() => Client.RegisterAsync(email, password, displayName));
        }

        public async Task<AuthResult<AuthSession>> LoginAsync(string email, string password)
        {
            return await RunBusyAsync(() => Client.LoginAsync(email, password));
        }

        public async Task<AuthResult<AuthSession>> UpgradeGuestAsync(string email, string password)
        {
            return await RunBusyAsync(() => Client.UpgradeGuestWithEmailAsync(email, password));
        }

        public async Task<AuthResult<bool>> SignOutAsync()
        {
            return await RunBusyAsync(() => Client.SignOutAsync());
        }

        /// <summary>
        /// Zero-argument helper directly bindable to a Canvas Button.onClick().
        /// </summary>
        public async void SignInAsGuest()
        {
            await SignInGuestAsync();
        }

        /// <summary>
        /// Zero-argument helper directly bindable to a Canvas Button.onClick().
        /// </summary>
        public async void SignOut()
        {
            await SignOutAsync();
        }

        /// <summary>
        /// Builds the UTF-8 connection payload for NGO NetworkConfig.ConnectionData, Mirror, or FishNet.
        /// </summary>
        public byte[] BuildMultiplayerConnectionPayload()
        {
            return MultiplayerAuthBridge.BuildClientConnectionPayload(CurrentSession, clientVersion);
        }

        private void EnsureInitialized()
        {
            if (_client != null) return;

            if (config != null)
            {
                _client = config.CreateClient(customAdapter: _injectedAdapter);
            }
            else if (_injectedAdapter != null)
            {
                var http = new Http.ApiHttpClient(new Http.UnityWebRequestTransport());
                _client = new AuthClient(_injectedAdapter, http);
            }
            else
            {
                _client = AuthClient.CreateMock(out _);
            }

            _client.OnSignedIn += s => onSignedIn?.Invoke(s);
            _client.OnSignedOut += () => onSignedOut?.Invoke();
            _client.OnSessionRefreshed += s => onSessionRefreshed?.Invoke(s);
            _client.OnProfileUpdated += p => onProfileUpdated?.Invoke(p);
            _client.OnAuthError += e => onAuthError?.Invoke(e);
        }

        private async Task<T> RunBusyAsync<T>(Func<Task<T>> operation)
        {
            onBusyStateChanged?.Invoke(true);
            try
            {
                return await operation();
            }
            finally
            {
                onBusyStateChanged?.Invoke(false);
            }
        }
    }
}
