using System;
using System.Threading;
using System.Threading.Tasks;
using UnityAuthCore.Core;
using UnityAuthCore.Http;
using UnityEngine;

namespace UnityAuthCore.Backends
{
    [Serializable]
    public sealed class RestEndpointMap
    {
        public string guestPath = "/v1/auth/guest";
        public string registerPath = "/v1/auth/register";
        public string loginPath = "/v1/auth/login";
        public string refreshPath = "/v1/auth/refresh";
        public string logoutPath = "/v1/auth/logout";
        public string profilePath = "/v1/account/me";
        public string linkEmailPath = "/v1/account/link";
        public string introspectPath = "/v1/auth/introspect";
    }

    /// <summary>
    /// Backend-agnostic REST implementation of IAuthBackendAdapter matching Docs~/openapi.yaml.
    /// Developers can point BaseUrl at the Dockerized reference server, any custom ASP.NET/Node/Go/FastAPI backend,
    /// or override endpoint paths via RestEndpointMap.
    /// </summary>
    public sealed class RestAuthBackendAdapter : IAuthBackendAdapter
    {
        [Serializable] private sealed class GuestReq { public string deviceId; public string displayName; }
        [Serializable] private sealed class RegisterReq { public string email; public string password; public string displayName; }
        [Serializable] private sealed class LoginReq { public string email; public string password; }
        [Serializable] private sealed class RefreshReq { public string refreshToken; }
        [Serializable] private sealed class LogoutReq { public string refreshToken; }
        [Serializable] private sealed class LinkEmailReq { public string email; public string password; }
        [Serializable] private sealed class IntrospectReq { public string accessToken; }

        private readonly ApiHttpClient _http;
        private readonly string _baseUrl;
        private readonly RestEndpointMap _endpoints;
        private readonly string _clientApiKey;

        public string ProviderId => "rest";

        public RestAuthBackendAdapter(
            ApiHttpClient http,
            string baseUrl,
            RestEndpointMap endpoints = null,
            string clientApiKey = null)
        {
            _http = http ?? throw new ArgumentNullException(nameof(http));
            _baseUrl = (baseUrl ?? "http://localhost:8080").TrimEnd('/');
            _endpoints = endpoints ?? new RestEndpointMap();
            _clientApiKey = clientApiKey;
        }

        public Task<AuthResult<AuthSession>> SignInGuestAsync(string deviceId, string displayName = null, CancellationToken ct = default)
        {
            var req = CreateRequest("POST", _endpoints.guestPath, new GuestReq
            {
                deviceId = string.IsNullOrWhiteSpace(deviceId) ? SystemInfo.deviceUniqueIdentifier : deviceId,
                displayName = displayName ?? string.Empty
            }, requiresAuth: false);

            return _http.SendJsonAsync<AuthSession>(req, ct);
        }

        public Task<AuthResult<AuthSession>> RegisterAsync(string email, string password, string displayName = null, CancellationToken ct = default)
        {
            var req = CreateRequest("POST", _endpoints.registerPath, new RegisterReq
            {
                email = email,
                password = password,
                displayName = displayName ?? string.Empty
            }, requiresAuth: false);

            return _http.SendJsonAsync<AuthSession>(req, ct);
        }

        public Task<AuthResult<AuthSession>> LoginAsync(string email, string password, CancellationToken ct = default)
        {
            var req = CreateRequest("POST", _endpoints.loginPath, new LoginReq
            {
                email = email,
                password = password
            }, requiresAuth: false);

            return _http.SendJsonAsync<AuthSession>(req, ct);
        }

        public Task<AuthResult<AuthSession>> RefreshAsync(string refreshToken, CancellationToken ct = default)
        {
            var req = CreateRequest("POST", _endpoints.refreshPath, new RefreshReq
            {
                refreshToken = refreshToken
            }, requiresAuth: false);
            req.SkipRetry = true;
            return _http.SendJsonAsync<AuthSession>(req, ct);
        }

        public Task<AuthResult<bool>> LogoutAsync(string accessToken, string refreshToken, CancellationToken ct = default)
        {
            var req = CreateRequest("POST", _endpoints.logoutPath, new LogoutReq
            {
                refreshToken = refreshToken
            }, requiresAuth: true);
            if (!string.IsNullOrEmpty(accessToken))
            {
                req.Headers["Authorization"] = $"Bearer {accessToken}";
            }
            req.SkipRetry = true;
            return _http.SendJsonAsync<bool>(req, ct);
        }

        public Task<AuthResult<AuthUserProfile>> GetProfileAsync(CancellationToken ct = default)
        {
            var req = CreateRequest("GET", _endpoints.profilePath, null, requiresAuth: true);
            return _http.SendJsonAsync<AuthUserProfile>(req, ct);
        }

        public Task<AuthResult<AuthUserProfile>> UpdateProfileAsync(AuthProfileUpdateRequest update, CancellationToken ct = default)
        {
            var req = CreateRequest("PATCH", _endpoints.profilePath, update ?? new AuthProfileUpdateRequest(), requiresAuth: true);
            return _http.SendJsonAsync<AuthUserProfile>(req, ct);
        }

        public Task<AuthResult<AuthSession>> LinkEmailPasswordAsync(string email, string password, CancellationToken ct = default)
        {
            var req = CreateRequest("POST", _endpoints.linkEmailPath, new LinkEmailReq
            {
                email = email,
                password = password
            }, requiresAuth: true);
            return _http.SendJsonAsync<AuthSession>(req, ct);
        }

        public Task<AuthResult<TokenValidationResult>> IntrospectTokenAsync(string accessToken, string serverApiKey = null, CancellationToken ct = default)
        {
            var req = CreateRequest("POST", _endpoints.introspectPath, new IntrospectReq
            {
                accessToken = accessToken
            }, requiresAuth: false);
            if (!string.IsNullOrEmpty(serverApiKey))
            {
                req.Headers["X-Server-Key"] = serverApiKey;
            }
            return _http.SendJsonAsync<TokenValidationResult>(req, ct);
        }

        private ApiRequest CreateRequest(string method, string path, object payload, bool requiresAuth)
        {
            string normalizedPath = string.IsNullOrEmpty(path) ? "/" : (path.StartsWith("/") ? path : "/" + path);
            var req = new ApiRequest
            {
                Method = method,
                Url = _baseUrl + normalizedPath,
                JsonBody = payload != null ? JsonUtility.ToJson(payload) : null,
                RequiresAuth = requiresAuth
            };

            if (!string.IsNullOrEmpty(_clientApiKey))
            {
                req.Headers["X-Api-Key"] = _clientApiKey;
            }

            return req;
        }
    }
}
