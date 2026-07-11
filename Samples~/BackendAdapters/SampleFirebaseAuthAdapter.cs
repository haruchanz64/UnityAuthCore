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

        public string ProviderId => "firebase";

        public SampleFirebaseAuthAdapter(ApiHttpClient http, string firebaseWebApiKey)
        {
            _http = http ?? throw new ArgumentNullException(nameof(http));
            _webApiKey = firebaseWebApiKey ?? string.Empty;
        }

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

        public Task<AuthResult<bool>> LogoutAsync(string accessToken, string refreshToken, CancellationToken ct = default)
        {
            return Task.FromResult(AuthResult<bool>.Ok(true, 204));
        }

        public Task<AuthResult<AuthUserProfile>> GetProfileAsync(CancellationToken ct = default)
        {
            return Task.FromResult(AuthResult<AuthUserProfile>.Fail(ApiError.Create(501, "NOT_IMPLEMENTED", "Extend SampleFirebaseAuthAdapter with accounts:lookup for profile queries.")));
        }

        public Task<AuthResult<AuthUserProfile>> UpdateProfileAsync(AuthProfileUpdateRequest update, CancellationToken ct = default)
        {
            return Task.FromResult(AuthResult<AuthUserProfile>.Fail(ApiError.Create(501, "NOT_IMPLEMENTED", "Extend SampleFirebaseAuthAdapter with accounts:update for profile updates.")));
        }

        public Task<AuthResult<AuthSession>> LinkEmailPasswordAsync(string email, string password, CancellationToken ct = default)
        {
            return Task.FromResult(AuthResult<AuthSession>.Fail(ApiError.Create(501, "NOT_IMPLEMENTED", "Extend SampleFirebaseAuthAdapter with accounts:update to link anonymous users.")));
        }

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
