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
    /// Starter IAuthBackendAdapter connecting UnityAuthCore directly to Supabase Auth (GoTrue REST API).
    /// Import this sample and inject it into AccountController.ConfigureCustomAdapter(...) or new AuthClient(...).
    /// </summary>
    public sealed class SampleSupabaseAuthAdapter : IAuthBackendAdapter
    {
        [Serializable] private sealed class CredsReq { public string email; public string password; }
        [Serializable] private sealed class RefreshReq { public string refresh_token; }
        [Serializable] private sealed class SupabaseUserDto { public string id; public string email; public bool is_anonymous; }
        [Serializable] private sealed class SupabaseSessionDto
        {
            public string access_token;
            public string refresh_token;
            public string token_type;
            public long expires_at;
            public SupabaseUserDto user;
        }

        private readonly ApiHttpClient _http;
        private readonly string _projectUrl;
        private readonly string _anonKey;

        public string ProviderId => "supabase";

        public SampleSupabaseAuthAdapter(ApiHttpClient http, string supabaseProjectUrl, string supabaseAnonKey)
        {
            _http = http ?? throw new ArgumentNullException(nameof(http));
            _projectUrl = (supabaseProjectUrl ?? string.Empty).TrimEnd('/');
            _anonKey = supabaseAnonKey ?? string.Empty;
        }

        public async Task<AuthResult<AuthSession>> SignInGuestAsync(string deviceId, string displayName = null, CancellationToken ct = default)
        {
            var req = BuildRequest("POST", "/auth/v1/signup", "{}", requiresAuth: false);
            return MapSession(await _http.SendJsonAsync<SupabaseSessionDto>(req, ct));
        }

        public async Task<AuthResult<AuthSession>> RegisterAsync(string email, string password, string displayName = null, CancellationToken ct = default)
        {
            var req = BuildRequest("POST", "/auth/v1/signup", JsonUtility.ToJson(new CredsReq { email = email, password = password }), requiresAuth: false);
            return MapSession(await _http.SendJsonAsync<SupabaseSessionDto>(req, ct));
        }

        public async Task<AuthResult<AuthSession>> LoginAsync(string email, string password, CancellationToken ct = default)
        {
            var req = BuildRequest("POST", "/auth/v1/token?grant_type=password", JsonUtility.ToJson(new CredsReq { email = email, password = password }), requiresAuth: false);
            return MapSession(await _http.SendJsonAsync<SupabaseSessionDto>(req, ct));
        }

        public async Task<AuthResult<AuthSession>> RefreshAsync(string refreshToken, CancellationToken ct = default)
        {
            var req = BuildRequest("POST", "/auth/v1/token?grant_type=refresh_token", JsonUtility.ToJson(new RefreshReq { refresh_token = refreshToken }), requiresAuth: false);
            req.SkipRetry = true;
            return MapSession(await _http.SendJsonAsync<SupabaseSessionDto>(req, ct));
        }

        public Task<AuthResult<bool>> LogoutAsync(string accessToken, string refreshToken, CancellationToken ct = default)
        {
            var req = BuildRequest("POST", "/auth/v1/logout", null, requiresAuth: true);
            return _http.SendJsonAsync<bool>(req, ct);
        }

        public async Task<AuthResult<AuthUserProfile>> GetProfileAsync(CancellationToken ct = default)
        {
            var req = BuildRequest("GET", "/auth/v1/user", null, requiresAuth: true);
            var res = await _http.SendJsonAsync<SupabaseUserDto>(req, ct);
            if (!res.Succeeded) return AuthResult<AuthUserProfile>.Fail(res.Error);
            return AuthResult<AuthUserProfile>.Ok(MapUser(res.Data), res.StatusCode);
        }

        public Task<AuthResult<AuthUserProfile>> UpdateProfileAsync(AuthProfileUpdateRequest update, CancellationToken ct = default)
        {
            return GetProfileAsync(ct);
        }

        public async Task<AuthResult<AuthSession>> LinkEmailPasswordAsync(string email, string password, CancellationToken ct = default)
        {
            var req = BuildRequest("PUT", "/auth/v1/user", JsonUtility.ToJson(new CredsReq { email = email, password = password }), requiresAuth: true);
            var res = await _http.SendJsonAsync<SupabaseUserDto>(req, ct);
            if (!res.Succeeded) return AuthResult<AuthSession>.Fail(res.Error);
            return AuthResult<AuthSession>.Ok(new AuthSession { providerId = ProviderId, user = MapUser(res.Data) }, res.StatusCode);
        }

        public async Task<AuthResult<TokenValidationResult>> IntrospectTokenAsync(string accessToken, string serverApiKey = null, CancellationToken ct = default)
        {
            var req = BuildRequest("GET", "/auth/v1/user", null, requiresAuth: false);
            req.Headers["Authorization"] = $"Bearer {accessToken}";
            var res = await _http.SendJsonAsync<SupabaseUserDto>(req, ct);
            if (!res.Succeeded || res.Data == null)
            {
                return AuthResult<TokenValidationResult>.Ok(new TokenValidationResult
                {
                    isValid = false,
                    failureCode = res.Error?.errorCode ?? "INVALID_TOKEN",
                    failureReason = res.Error?.message ?? "Supabase token validation failed."
                });
            }

            return AuthResult<TokenValidationResult>.Ok(new TokenValidationResult
            {
                isValid = true,
                accountId = res.Data.id,
                displayName = res.Data.email,
                isGuest = res.Data.is_anonymous,
                roles = new List<string> { "authenticated" }
            });
        }

        private ApiRequest BuildRequest(string method, string path, string jsonBody, bool requiresAuth)
        {
            var req = new ApiRequest
            {
                Method = method,
                Url = _projectUrl + path,
                JsonBody = jsonBody,
                RequiresAuth = requiresAuth
            };
            req.Headers["apikey"] = _anonKey;
            return req;
        }

        private AuthResult<AuthSession> MapSession(AuthResult<SupabaseSessionDto> res)
        {
            if (!res.Succeeded || res.Data == null) return AuthResult<AuthSession>.Fail(res.Error);
            return AuthResult<AuthSession>.Ok(new AuthSession
            {
                accessToken = res.Data.access_token,
                refreshToken = res.Data.refresh_token,
                tokenType = string.IsNullOrEmpty(res.Data.token_type) ? "Bearer" : res.Data.token_type,
                expiresAtUnixSeconds = res.Data.expires_at,
                providerId = ProviderId,
                user = MapUser(res.Data.user)
            }, res.StatusCode);
        }

        private static AuthUserProfile MapUser(SupabaseUserDto u)
        {
            if (u == null) return new AuthUserProfile();
            return new AuthUserProfile
            {
                accountId = u.id,
                email = u.email,
                displayName = string.IsNullOrEmpty(u.email) ? u.id : u.email.Split('@')[0],
                isGuest = u.is_anonymous,
                roles = new List<string> { "authenticated" }
            };
        }
    }
}
