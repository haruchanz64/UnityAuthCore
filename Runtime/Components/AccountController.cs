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
    /// <summary>Serializable <see cref="UnityEvent{T0}"/> carrying an <see cref="AuthSession"/> payload.</summary>
    [Serializable] public sealed class AuthSessionUnityEvent : UnityEvent<AuthSession> { }
    /// <summary>Serializable <see cref="UnityEvent{T0}"/> carrying an <see cref="AuthUserProfile"/> payload.</summary>
    [Serializable] public sealed class AuthProfileUnityEvent : UnityEvent<AuthUserProfile> { }
    /// <summary>Serializable <see cref="UnityEvent{T0}"/> carrying an <see cref="ApiError"/> payload.</summary>
    [Serializable] public sealed class AuthErrorUnityEvent : UnityEvent<ApiError> { }
    /// <summary>Serializable <see cref="UnityEvent{T0}"/> reporting busy state transitions (true while an auth request is running).</summary>
    [Serializable] public sealed class AuthBusyUnityEvent : UnityEvent<bool> { }

    /// <summary>
    /// Drop-in MonoBehaviour wiring <see cref="AuthClient"/> to uGUI Canvas screens, 3D scenes, or multiplayer boot flows.
    /// Supports custom <see cref="IAuthBackendAdapter"/> injection so developers can plug in any self-hosted or BaaS provider.
    /// </summary>
    [DisallowMultipleComponent]
    public sealed class AccountController : MonoBehaviour
    {
        [Header("Configuration")]
        [SerializeField] private AuthFrameworkConfig config;
        [SerializeField] private bool restoreSessionOnStart = true;
        [SerializeField] private string clientVersion = "1.0.0";

        /// <summary>Invoked in the Inspector when a session is restored, signed in, registered, or upgraded.</summary>
        [Header("Inspector Events (Canvas / Scene / Multiplayer Hooks)")]
        public AuthSessionUnityEvent onSignedIn = new AuthSessionUnityEvent();
        /// <summary>Invoked when the local session is cleared on sign-out or failed refresh.</summary>
        public UnityEvent onSignedOut = new UnityEvent();
        /// <summary>Invoked when the active session tokens are rotated.</summary>
        public AuthSessionUnityEvent onSessionRefreshed = new AuthSessionUnityEvent();
        /// <summary>Invoked when profile data is fetched or updated.</summary>
        public AuthProfileUnityEvent onProfileUpdated = new AuthProfileUnityEvent();
        /// <summary>Invoked whenever an authentication or profile request fails.</summary>
        public AuthErrorUnityEvent onAuthError = new AuthErrorUnityEvent();
        /// <summary>Invoked with true before an async auth operation starts and false in its finally block.</summary>
        public AuthBusyUnityEvent onBusyStateChanged = new AuthBusyUnityEvent();

        private AuthClient _client;
        private IAuthBackendAdapter _injectedAdapter;

        /// <summary>Lazily initialized <see cref="AuthClient"/> managed by this component.</summary>
        public AuthClient Client
        {
            get
            {
                EnsureInitialized();
                return _client;
            }
        }

        /// <summary>True when the underlying <see cref="Client"/> has a non-empty access token.</summary>
        public bool IsSignedIn => Client.IsSignedIn;
        /// <summary>Active <see cref="AuthSession"/> from <see cref="Client"/>, or null when signed out.</summary>
        public AuthSession CurrentSession => Client.CurrentSession;

        /// <summary>
        /// Replaces the backend adapter and rebuilds the underlying <see cref="AuthClient"/> immediately.
        /// </summary>
        /// <param name="customAdapter">Custom <see cref="IAuthBackendAdapter"/> implementation (for example, Supabase, Firebase, or PlayFab).</param>
        public void ConfigureCustomAdapter(IAuthBackendAdapter customAdapter)
        {
            _injectedAdapter = customAdapter;
            _client = null;
            EnsureInitialized();
        }

        /// <summary>
        /// Assigns a new <see cref="AuthFrameworkConfig"/> asset and rebuilds the underlying <see cref="AuthClient"/>.
        /// </summary>
        /// <param name="frameworkConfig">Configuration asset to apply, or null to fall back to mock/custom defaults.</param>
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

        /// <summary>
        /// Restores any persisted session from the configured token store while toggling <see cref="onBusyStateChanged"/>.
        /// </summary>
        /// <returns>The restored or refreshed <see cref="AuthSession"/> result.</returns>
        public async Task<AuthResult<AuthSession>> InitializeSessionAsync()
        {
            return await RunBusyAsync(() => Client.InitializeAsync());
        }

        /// <summary>
        /// Signs into or creates a guest account using <see cref="SystemInfo.deviceUniqueIdentifier"/>.
        /// </summary>
        /// <param name="displayName">Optional display name for new guest accounts.</param>
        /// <returns>The authentication result containing the guest session or error details.</returns>
        public async Task<AuthResult<AuthSession>> SignInGuestAsync(string displayName = null)
        {
            return await RunBusyAsync(() => Client.SignInGuestAsync(SystemInfo.deviceUniqueIdentifier, displayName));
        }

        /// <summary>
        /// Registers a new email and password account while toggling <see cref="onBusyStateChanged"/>.
        /// </summary>
        /// <param name="email">Player email address.</param>
        /// <param name="password">Account password.</param>
        /// <param name="displayName">Optional initial display name.</param>
        /// <returns>The registration result containing the created session or error details.</returns>
        public async Task<AuthResult<AuthSession>> RegisterAsync(string email, string password, string displayName = null)
        {
            return await RunBusyAsync(() => Client.RegisterAsync(email, password, displayName));
        }

        /// <summary>
        /// Authenticates an existing account with email and password while toggling <see cref="onBusyStateChanged"/>.
        /// </summary>
        /// <param name="email">Registered email address.</param>
        /// <param name="password">Account password.</param>
        /// <returns>The login result containing the active session or error details.</returns>
        public async Task<AuthResult<AuthSession>> LoginAsync(string email, string password)
        {
            return await RunBusyAsync(() => Client.LoginAsync(email, password));
        }

        /// <summary>
        /// Upgrades the active guest account by linking email and password credentials.
        /// </summary>
        /// <param name="email">Email address to link.</param>
        /// <param name="password">Password to set for the account.</param>
        /// <returns>The upgraded session result or error details.</returns>
        public async Task<AuthResult<AuthSession>> UpgradeGuestAsync(string email, string password)
        {
            return await RunBusyAsync(() => Client.UpgradeGuestWithEmailAsync(email, password));
        }

        /// <summary>
        /// Signs out of the backend and clears local token storage while toggling <see cref="onBusyStateChanged"/>.
        /// </summary>
        /// <returns>The backend logout result.</returns>
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
        /// <returns>Serialized <see cref="MultiplayerAuthTicket"/> bytes, or an empty array when signed out.</returns>
        public byte[] BuildMultiplayerConnectionPayload()
        {
            return MultiplayerAuthBridge.BuildClientConnectionPayload(CurrentSession, clientVersion);
        }

        /// <summary>
        /// Lazily constructs <see cref="_client"/> from <see cref="config"/>, an injected adapter, or an in-process mock fallback, and forwards its events to Inspector UnityEvents.
        /// </summary>
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

        /// <summary>
        /// Wraps an asynchronous operation with <see cref="onBusyStateChanged"/> notifications.
        /// </summary>
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
