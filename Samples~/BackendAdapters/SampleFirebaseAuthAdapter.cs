using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using UnityAuthCore.Core;
using UnityAuthCore.Http;
using UnityEngine;

namespace UnityAuthCore.Samples.Backends
{
    /// <summary>
    /// Starter IAuthBackendAdapter connecting UnityAuthCore directly to Firebase Identity Toolkit REST API.
    /// Import this sample and inject it into AccountController.ConfigureCustomAdapter(...) or new AuthClient(...).
    /// </summary>
    public sealed class SampleFirebaseAuthAdapter : IAuthBackendAdapter
    {
        [Serializable] private sealed class FirebaseAuthReq { public string email; public string password; public bool returnSecureToken = true; }
        [Serializable] private sealed class FirebaseAnonReq { public bool returnSecureToken = true; }
        [Serializable] private sealed class FirebaseRefreshReq { public string grant_type = "refresh_token"; public string refresh_token; }
        [Serializable] private sealed class FirebaseLookupReq { public string idToken; }

        [Serializable] private sealed class FirebaseAuthResp
        {
            public string localId;
            public string email;
            public string displayName;
            public string idToken;
            public string refreshToken;
            public string expiresIn;
        }

        [Serializable] private sealed class FirebaseRefreshResp
        {
            public string id_token;
            public string refresh_token;
            public string expires_in;
            public string user_id;
        }

        private readonly ApiHttpClient _http;
        private readonly string _webApiKey;

        /// <inheritdoc/>
        public string ProviderId => "firebase";

        /// <summary>
        /// Initializes a starter Firebase Identity Toolkit REST adapter.
        /// </summary>
        /// <param name="http">HTTP client pipeline used to dispatch requests.</param>
        /// <param name="firebaseWebApiKey">Firebase project Web API key appended to Identity Toolkit and Secure Token URLs.</param>
        public SampleFirebaseAuthAdapter(ApiHttpClient http, string firebaseWebApiKey)
        {
            _http = http ?? throw new ArgumentNullException(nameof(http));
            _webApiKey = firebaseWebApiKey ?? string.Empty;
        }

        /// <inheritdoc/>
        public async Task<AuthResult<AuthSession>> SignInGuestAsync(string deviceId, string displayName = null, CancellationToken ct = default)
        {
            var req = new ApiRequest
            {
                Method = "POST",
                Url = $"https://identitytoolkit.googleapis.com/v1/accounts:signUp?key={_webApiKey}",
                JsonBody = JsonUtility.ToJson(new FirebaseAnonReq())
            };
            return MapAuthResponse(await _http.SendJsonAsync<FirebaseAuthResp>(req, ct), isGuest: true);
        }

        /// <inheritdoc/>
        public async Task<AuthResult<AuthSession>> RegisterAsync(string email, string password, string displayName = null, CancellationToken ct = default)
        {
            var req = new ApiRequest
            {
                Method = "POST",
                Url = $"https://identitytoolkit.googleapis.com/v1/accounts:signUp?key={_webApiKey}",
                JsonBody = JsonUtility.ToJson(new FirebaseAuthReq { email = email, password = password })
            };
            return MapAuthResponse(await _http.SendJsonAsync<FirebaseAuthResp>(req, ct), isGuest: false);
        }

        /// <inheritdoc/>
        public async Task<AuthResult<AuthSession>> LoginAsync(string email, string password, CancellationToken ct = default)
        {
            var req = new ApiRequest
            {
                Method = "POST",
                Url = $"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={_webApiKey}",
                JsonBody = JsonUtility.ToJson(new FirebaseAuthReq { email = email, password = password })
            };
            return MapAuthResponse(await _http.SendJsonAsync<FirebaseAuthResp>(req, ct), isGuest: false);
        }

        /// <inheritdoc/>
        public async Task<AuthResult<AuthSession>> RefreshAsync(string refreshToken, CancellationToken ct = default)
        {
            var req = new ApiRequest
            {
                Method = "POST",
                Url = $"https://securetoken.googleapis.com/v1/token?key={_webApiKey}",
                JsonBody = JsonUtility.ToJson(new FirebaseRefreshReq { refresh_token = refreshToken }),
                SkipRetry = true
            };
            var res = await _http.SendJsonAsync<FirebaseRefreshResp>(req, ct);
            if (!res.Succeeded || res.Data == null) return AuthResult<AuthSession>.Fail(res.Error);

            long ttl = long.TryParse(res.Data.expires_in, out long s) ? s : 3600;
            return AuthResult<AuthSession>.Ok(new AuthSession
            {
                accessToken = res.Data.id_token,
                refreshToken = res.Data.refresh_token,
                expiresAtUnixSeconds = DateTimeOffset.UtcNow.ToUnixTimeSeconds() + ttl,
                providerId = ProviderId,
                user = new AuthUserProfile { accountId = res.Data.user_id }
            }, res.StatusCode);
        }

        /// <summary>
        /// Completes immediately with HTTP 204 because Firebase ID tokens are stateless on the client until expiry.
        /// </summary>
        public Task<AuthResult<bool>> LogoutAsync(string accessToken, string refreshToken, CancellationToken ct = default)
        {
            return Task.FromResult(AuthResult<bool>.Ok(true, 204));
        }

        /// <summary>
        /// Starter stub returning HTTP 501; extend with <c>accounts:lookup</c> to query full Firebase profiles.
        /// </summary>
        public Task<AuthResult<AuthUserProfile>> GetProfileAsync(CancellationToken ct = default)
        {
            return Task.FromResult(AuthResult<AuthUserProfile>.Fail(ApiError.Create(501, "NOT_IMPLEMENTED", "Extend SampleFirebaseAuthAdapter with accounts:lookup for profile queries.")));
        }

        /// <summary>
        /// Starter stub returning HTTP 501; extend with <c>accounts:update</c> to persist profile changes.
        /// </summary>
        public Task<AuthResult<AuthUserProfile>> UpdateProfileAsync(AuthProfileUpdateRequest update, CancellationToken ct = default)
        {
            return Task.FromResult(AuthResult<AuthUserProfile>.Fail(ApiError.Create(501, "NOT_IMPLEMENTED", "Extend SampleFirebaseAuthAdapter with accounts:update for profile updates.")));
        }

        /// <summary>
        /// Starter stub returning HTTP 501; extend with <c>accounts:update</c> to link email credentials to an anonymous Firebase user.
        /// </summary>
        public Task<AuthResult<AuthSession>> LinkEmailPasswordAsync(string email, string password, CancellationToken ct = default)
        {
            return Task.FromResult(AuthResult<AuthSession>.Fail(ApiError.Create(501, "NOT_IMPLEMENTED", "Extend SampleFirebaseAuthAdapter with accounts:update to link anonymous users.")));
        }

        /// <inheritdoc/>
        public async Task<AuthResult<TokenValidationResult>> IntrospectTokenAsync(string accessToken, string serverApiKey = null, CancellationToken ct = default)
        {
            var req = new ApiRequest
            {
                Method = "POST",
                Url = $"https://identitytoolkit.googleapis.com/v1/accounts:lookup?key={_webApiKey}",
                JsonBody = JsonUtility.ToJson(new FirebaseLookupReq { idToken = accessToken })
            };
            var raw = await _http.SendRawAsync(req, ct);
            return AuthResult<TokenValidationResult>.Ok(new TokenValidationResult
            {
                isValid = raw.IsSuccess,
                failureCode = raw.IsSuccess ? string.Empty : "INVALID_FIREBASE_TOKEN",
                failureReason = raw.IsSuccess ? string.Empty : raw.Body
            });
        }

        /// <summary>
        /// Maps a Firebase Identity Toolkit sign-up or sign-in response into an <see cref="AuthSession"/>.
        /// </summary>
        private AuthResult<AuthSession> MapAuthResponse(AuthResult<FirebaseAuthResp> res, bool isGuest)
        {
            if (!res.Succeeded || res.Data == null) return AuthResult<AuthSession>.Fail(res.Error);
            long ttl = long.TryParse(res.Data.expiresIn, out long s) ? s : 3600;
            return AuthResult<AuthSession>.Ok(new AuthSession
            {
                accessToken = res.Data.idToken,
                refreshToken = res.Data.refreshToken,
                expiresAtUnixSeconds = DateTimeOffset.UtcNow.ToUnixTimeSeconds() + ttl,
                providerId = ProviderId,
                user = new AuthUserProfile
                {
                    accountId = res.Data.localId,
                    email = res.Data.email,
                    displayName = string.IsNullOrEmpty(res.Data.displayName) ? res.Data.email : res.Data.displayName,
                    isGuest = isGuest,
                    roles = new List<string> { "player" }
                }
            }, res.StatusCode);
        }
    }
}
