using System;
using System.Threading;
using System.Threading.Tasks;
using UnityAuthCore.Backends;
using UnityAuthCore.Core;
using UnityAuthCore.Http;
using UnityAuthCore.Security;

namespace UnityAuthCore.Engine
{
    /// <summary>
    /// High-level backend-agnostic authentication and session manager.
    /// Coordinates IAuthBackendAdapter, ApiHttpClient (with single-flight 401 refresh), and ITokenStore.
    /// </summary>
    public sealed class AuthClient
    {
        private readonly IAuthBackendAdapter _adapter;
        private readonly ITokenStore _tokenStore;
        private readonly ApiHttpClient _httpClient;
        private readonly int _refreshSkewSeconds;
        private readonly Func<DateTime> _utcNow;

        /// <summary>Currently active session, or null when signed out.</summary>
        public AuthSession CurrentSession { get; private set; }
        /// <summary>True when <see cref="CurrentSession"/> is present and contains a non-empty access token.</summary>
        public bool IsSignedIn => CurrentSession != null && CurrentSession.HasAccessToken;
        /// <summary>Underlying backend adapter used for authentication and profile requests.</summary>
        public IAuthBackendAdapter Adapter => _adapter;
        /// <summary>HTTP client configured with Bearer authentication and single-flight 401 refresh.</summary>
        public ApiHttpClient HttpClient => _httpClient;
        /// <summary>Token store used to persist and clear <see cref="CurrentSession"/>.</summary>
        public ITokenStore TokenStore => _tokenStore;

        /// <summary>Raised when a new session is established via restore, guest sign-in, register, login, or account upgrade.</summary>
        public event Action<AuthSession> OnSignedIn;
        /// <summary>Raised after the local session is cleared on sign-out or unrecoverable refresh failure.</summary>
        public event Action OnSignedOut;
        /// <summary>Raised when <see cref="RefreshSessionAsync"/> rotates the active session.</summary>
        public event Action<AuthSession> OnSessionRefreshed;
        /// <summary>Raised when profile retrieval or update refreshes <see cref="AuthSession.user"/>.</summary>
        public event Action<AuthUserProfile> OnProfileUpdated;
        /// <summary>Raised whenever an authentication, refresh, or profile operation fails.</summary>
        public event Action<ApiError> OnAuthError;

        /// <summary>
        /// Initializes a new <see cref="AuthClient"/>, attaching <see cref="BearerAuthInterceptor"/> and single-flight 401 refresh to <paramref name="httpClient"/>.
        /// </summary>
        /// <param name="adapter">Backend adapter implementing authentication endpoints.</param>
        /// <param name="httpClient">HTTP pipeline shared with the adapter.</param>
        /// <param name="tokenStore">Optional session store; defaults to <see cref="InMemoryTokenStore"/>.</param>
        /// <param name="refreshSkewSeconds">Lead time in seconds before token expiry to trigger proactive refresh.</param>
        /// <param name="utcNowProvider">Optional UTC clock provider for deterministic tests.</param>
        public AuthClient(
            IAuthBackendAdapter adapter,
            ApiHttpClient httpClient,
            ITokenStore tokenStore = null,
            int refreshSkewSeconds = 30,
            Func<DateTime> utcNowProvider = null)
        {
            _adapter = adapter ?? throw new ArgumentNullException(nameof(adapter));
            _httpClient = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
            _tokenStore = tokenStore ?? new InMemoryTokenStore();
            _refreshSkewSeconds = Math.Max(0, refreshSkewSeconds);
            _utcNow = utcNowProvider ?? (() => DateTime.UtcNow);

            _httpClient.AddInterceptor(new BearerAuthInterceptor(() => CurrentSession?.accessToken));
            _httpClient.OnUnauthorizedRefreshAsync = HandleSingleFlightUnauthorizedRefreshAsync;
        }

        /// <summary>
        /// Convenience factory for zero-setup in-process mock auth (useful for Editor tools and tests).
        /// </summary>
        /// <param name="mockTransport">Outputs the created <see cref="MockAuthTransport"/> for fault injection or metrics inspection.</param>
        /// <param name="tokenStore">Optional token store; defaults to <see cref="InMemoryTokenStore"/>.</param>
        /// <param name="utcNowProvider">Optional UTC clock provider shared by both the mock server and client.</param>
        /// <returns>An <see cref="AuthClient"/> wired to <paramref name="mockTransport"/>.</returns>
        public static AuthClient CreateMock(
            out MockAuthTransport mockTransport,
            ITokenStore tokenStore = null,
            Func<DateTime> utcNowProvider = null)
        {
            mockTransport = new MockAuthTransport(utcNowProvider);
            var http = new ApiHttpClient(mockTransport);
            var adapter = new RestAuthBackendAdapter(http, "http://mock.local");
            return new AuthClient(adapter, http, tokenStore, 30, utcNowProvider);
        }

        /// <summary>
        /// Restores any previously persisted session from <see cref="ITokenStore"/> and refreshes it if near expiry.
        /// Clears stored credentials if the access token is expired and no refresh token exists.
        /// </summary>
        /// <param name="ct">Optional cancellation token.</param>
        /// <returns>Succeeded result with the active session, or a 401 failure when no valid session can be restored.</returns>
        public async Task<AuthResult<AuthSession>> InitializeAsync(CancellationToken ct = default)
        {
            AuthSession stored = await _tokenStore.LoadAsync(ct);
            if (stored == null || (!stored.HasAccessToken && !stored.HasRefreshToken))
            {
                return AuthResult<AuthSession>.Fail(ApiError.Create(401, "NO_SAVED_SESSION", "No persisted session found."));
            }

            CurrentSession = stored;
            if (CurrentSession.IsAccessTokenExpired(_refreshSkewSeconds, _utcNow()))
            {
                if (!CurrentSession.HasRefreshToken)
                {
                    await ClearSessionLocalAsync(ct);
                    return AuthResult<AuthSession>.Fail(ApiError.Create(401, "SESSION_EXPIRED", "Saved session expired without a refresh token."));
                }

                return await RefreshSessionAsync(ct);
            }

            OnSignedIn?.Invoke(CurrentSession);
            return AuthResult<AuthSession>.Ok(CurrentSession);
        }

        /// <summary>
        /// Signs into or creates a guest account, persists the resulting session, and raises <see cref="OnSignedIn"/>.
        /// </summary>
        /// <param name="deviceId">Optional device identifier; null delegates fallback generation to the adapter.</param>
        /// <param name="displayName">Optional display name for new guest accounts.</param>
        /// <param name="ct">Optional cancellation token.</param>
        /// <returns>The authentication result containing the guest session or error details.</returns>
        public async Task<AuthResult<AuthSession>> SignInGuestAsync(string deviceId = null, string displayName = null, CancellationToken ct = default)
        {
            var res = await _adapter.SignInGuestAsync(deviceId, displayName, ct);
            return await HandleSessionResultAsync(res, isRefresh: false, ct);
        }

        /// <summary>
        /// Registers a new email/password account, persists the session, and raises <see cref="OnSignedIn"/>.
        /// </summary>
        /// <param name="email">Email address for the new account.</param>
        /// <param name="password">Account password.</param>
        /// <param name="displayName">Optional initial display name.</param>
        /// <param name="ct">Optional cancellation token.</param>
        /// <returns>The registration result containing the created session or error details.</returns>
        public async Task<AuthResult<AuthSession>> RegisterAsync(string email, string password, string displayName = null, CancellationToken ct = default)
        {
            var res = await _adapter.RegisterAsync(email, password, displayName, ct);
            return await HandleSessionResultAsync(res, isRefresh: false, ct);
        }

        /// <summary>
        /// Authenticates an existing account with email and password, persists the session, and raises <see cref="OnSignedIn"/>.
        /// </summary>
        /// <param name="email">Registered email address.</param>
        /// <param name="password">Account password.</param>
        /// <param name="ct">Optional cancellation token.</param>
        /// <returns>The login result containing the active session or error details.</returns>
        public async Task<AuthResult<AuthSession>> LoginAsync(string email, string password, CancellationToken ct = default)
        {
            var res = await _adapter.LoginAsync(email, password, ct);
            return await HandleSessionResultAsync(res, isRefresh: false, ct);
        }

        /// <summary>
        /// Rotates the active session using <see cref="AuthSession.refreshToken"/>.
        /// Clears local session state and raises <see cref="OnSignedOut"/> and <see cref="OnAuthError"/> if refresh fails.
        /// </summary>
        /// <param name="ct">Optional cancellation token.</param>
        /// <returns>The refreshed session result, or a failure if no refresh token is available or the server rejects it.</returns>
        public async Task<AuthResult<AuthSession>> RefreshSessionAsync(CancellationToken ct = default)
        {
            if (CurrentSession == null || !CurrentSession.HasRefreshToken)
            {
                var err = ApiError.Create(401, "NO_REFRESH_TOKEN", "No refresh token available.");
                OnAuthError?.Invoke(err);
                return AuthResult<AuthSession>.Fail(err);
            }

            var res = await _adapter.RefreshAsync(CurrentSession.refreshToken, ct);
            if (!res.Succeeded)
            {
                await ClearSessionLocalAsync(ct);
                OnAuthError?.Invoke(res.Error);
                return res;
            }

            return await HandleSessionResultAsync(res, isRefresh: true, ct);
        }

        /// <summary>
        /// Fetches the authenticated user's profile after ensuring the access token is fresh, updating cached session state on success.
        /// </summary>
        /// <param name="ct">Optional cancellation token.</param>
        /// <returns>The fetched <see cref="AuthUserProfile"/> or error details.</returns>
        public async Task<AuthResult<AuthUserProfile>> GetProfileAsync(CancellationToken ct = default)
        {
            await EnsureValidAccessTokenAsync(ct);
            var res = await _adapter.GetProfileAsync(ct);
            if (res.Succeeded && CurrentSession != null && res.Data != null)
            {
                CurrentSession.user = res.Data;
                await _tokenStore.SaveAsync(CurrentSession, ct);
                OnProfileUpdated?.Invoke(res.Data);
            }
            else if (!res.Succeeded)
            {
                OnAuthError?.Invoke(res.Error);
            }
            return res;
        }

        /// <summary>
        /// Sends a partial profile update after ensuring the access token is fresh, persisting the updated profile on success.
        /// </summary>
        /// <param name="update">Fields to update on the user's profile.</param>
        /// <param name="ct">Optional cancellation token.</param>
        /// <returns>The updated <see cref="AuthUserProfile"/> or error details.</returns>
        public async Task<AuthResult<AuthUserProfile>> UpdateProfileAsync(AuthProfileUpdateRequest update, CancellationToken ct = default)
        {
            await EnsureValidAccessTokenAsync(ct);
            var res = await _adapter.UpdateProfileAsync(update, ct);
            if (res.Succeeded && CurrentSession != null && res.Data != null)
            {
                CurrentSession.user = res.Data;
                await _tokenStore.SaveAsync(CurrentSession, ct);
                OnProfileUpdated?.Invoke(res.Data);
            }
            else if (!res.Succeeded)
            {
                OnAuthError?.Invoke(res.Error);
            }
            return res;
        }

        /// <summary>
        /// Links email and password credentials to the current guest session and persists the upgraded session.
        /// </summary>
        /// <param name="email">Email address to attach to the current account.</param>
        /// <param name="password">Password to set for the account.</param>
        /// <param name="ct">Optional cancellation token.</param>
        /// <returns>The upgraded session result or error details.</returns>
        public async Task<AuthResult<AuthSession>> UpgradeGuestWithEmailAsync(string email, string password, CancellationToken ct = default)
        {
            await EnsureValidAccessTokenAsync(ct);
            var res = await _adapter.LinkEmailPasswordAsync(email, password, ct);
            return await HandleSessionResultAsync(res, isRefresh: false, ct);
        }

        /// <summary>
        /// Revokes the active session on the backend (when tokens exist) and always clears local session storage.
        /// </summary>
        /// <param name="ct">Optional cancellation token.</param>
        /// <returns>Backend logout response; local state is cleared even if the server request fails.</returns>
        public async Task<AuthResult<bool>> SignOutAsync(CancellationToken ct = default)
        {
            string access = CurrentSession?.accessToken;
            string refresh = CurrentSession?.refreshToken;

            AuthResult<bool> res = AuthResult<bool>.Ok(true);
            if (!string.IsNullOrEmpty(access) || !string.IsNullOrEmpty(refresh))
            {
                res = await _adapter.LogoutAsync(access, refresh, ct);
            }

            await ClearSessionLocalAsync(ct);
            return res;
        }

        /// <summary>
        /// Forces the local access token expiry timestamp into the past (useful for testing auto-refresh flows).
        /// </summary>
        public void ForceExpireLocalAccessToken()
        {
            if (CurrentSession != null)
            {
                CurrentSession.expiresAtUnixSeconds = 1;
            }
        }

        /// <summary>
        /// Decodes the current session's JWT claims without verifying the signature.
        /// </summary>
        /// <param name="claims">Outputs the decoded <see cref="JwtClaims"/> on success; otherwise null.</param>
        /// <param name="error">Outputs a diagnostic error message on failure; otherwise null.</param>
        /// <returns>True if the current access token is a valid three-segment JWT payload.</returns>
        public bool TryDecodeCurrentClaims(out JwtClaims claims, out string error)
        {
            return JwtUtility.TryParseClaims(CurrentSession?.accessToken, out claims, out error);
        }

        /// <summary>
        /// Proactively refreshes the session before protected calls when the access token is within the configured expiry skew.
        /// </summary>
        private async Task EnsureValidAccessTokenAsync(CancellationToken ct)
        {
            if (CurrentSession != null &&
                CurrentSession.HasRefreshToken &&
                CurrentSession.IsAccessTokenExpired(_refreshSkewSeconds, _utcNow()))
            {
                await RefreshSessionAsync(ct);
            }
        }

        /// <summary>
        /// Callback registered with <see cref="ApiHttpClient.OnUnauthorizedRefreshAsync"/> to coalesce concurrent 401 refresh attempts.
        /// </summary>
        private async Task<bool> HandleSingleFlightUnauthorizedRefreshAsync(CancellationToken ct)
        {
            if (CurrentSession == null || !CurrentSession.HasRefreshToken)
            {
                return false;
            }

            var res = await RefreshSessionAsync(ct);
            return res.Succeeded;
        }

        /// <summary>
        /// Applies an auth or refresh response to <see cref="CurrentSession"/>, persists it, and dispatches lifecycle events.
        /// </summary>
        private async Task<AuthResult<AuthSession>> HandleSessionResultAsync(AuthResult<AuthSession> res, bool isRefresh, CancellationToken ct)
        {
            if (!res.Succeeded || res.Data == null)
            {
                OnAuthError?.Invoke(res.Error);
                return res;
            }

            CurrentSession = res.Data;
            await _tokenStore.SaveAsync(CurrentSession, ct);

            if (isRefresh)
            {
                OnSessionRefreshed?.Invoke(CurrentSession);
            }
            else
            {
                OnSignedIn?.Invoke(CurrentSession);
            }

            return res;
        }

        /// <summary>
        /// Clears in-memory and persisted session data and raises <see cref="OnSignedOut"/>.
        /// </summary>
        private async Task ClearSessionLocalAsync(CancellationToken ct)
        {
            CurrentSession = null;
            await _tokenStore.ClearAsync(ct);
            OnSignedOut?.Invoke();
        }
    }
}
