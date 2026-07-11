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

        public AuthSession CurrentSession { get; private set; }
        public bool IsSignedIn => CurrentSession != null && CurrentSession.HasAccessToken;
        public IAuthBackendAdapter Adapter => _adapter;
        public ApiHttpClient HttpClient => _httpClient;
        public ITokenStore TokenStore => _tokenStore;

        public event Action<AuthSession> OnSignedIn;
        public event Action OnSignedOut;
        public event Action<AuthSession> OnSessionRefreshed;
        public event Action<AuthUserProfile> OnProfileUpdated;
        public event Action<ApiError> OnAuthError;

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
        /// Convenience factory for zero-setup in-process mock auth (useful for Editor tools & tests).
        /// </summary>
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
        /// Restores any previously persisted session from ITokenStore and refreshes it if near expiry.
        /// </summary>
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

        public async Task<AuthResult<AuthSession>> SignInGuestAsync(string deviceId = null, string displayName = null, CancellationToken ct = default)
        {
            var res = await _adapter.SignInGuestAsync(deviceId, displayName, ct);
            return await HandleSessionResultAsync(res, isRefresh: false, ct);
        }

        public async Task<AuthResult<AuthSession>> RegisterAsync(string email, string password, string displayName = null, CancellationToken ct = default)
        {
            var res = await _adapter.RegisterAsync(email, password, displayName, ct);
            return await HandleSessionResultAsync(res, isRefresh: false, ct);
        }

        public async Task<AuthResult<AuthSession>> LoginAsync(string email, string password, CancellationToken ct = default)
        {
            var res = await _adapter.LoginAsync(email, password, ct);
            return await HandleSessionResultAsync(res, isRefresh: false, ct);
        }

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

        public async Task<AuthResult<AuthSession>> UpgradeGuestWithEmailAsync(string email, string password, CancellationToken ct = default)
        {
            await EnsureValidAccessTokenAsync(ct);
            var res = await _adapter.LinkEmailPasswordAsync(email, password, ct);
            return await HandleSessionResultAsync(res, isRefresh: false, ct);
        }

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

        public bool TryDecodeCurrentClaims(out JwtClaims claims, out string error)
        {
            return JwtUtility.TryParseClaims(CurrentSession?.accessToken, out claims, out error);
        }

        private async Task EnsureValidAccessTokenAsync(CancellationToken ct)
        {
            if (CurrentSession != null &&
                CurrentSession.HasRefreshToken &&
                CurrentSession.IsAccessTokenExpired(_refreshSkewSeconds, _utcNow()))
            {
                await RefreshSessionAsync(ct);
            }
        }

        private async Task<bool> HandleSingleFlightUnauthorizedRefreshAsync(CancellationToken ct)
        {
            if (CurrentSession == null || !CurrentSession.HasRefreshToken)
            {
                return false;
            }

            var res = await RefreshSessionAsync(ct);
            return res.Succeeded;
        }

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

        private async Task ClearSessionLocalAsync(CancellationToken ct)
        {
            CurrentSession = null;
            await _tokenStore.ClearAsync(ct);
            OnSignedOut?.Invoke();
        }
    }
}
