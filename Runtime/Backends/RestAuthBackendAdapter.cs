using System;
using System.Threading;
using System.Threading.Tasks;
using UnityAuthCore.Core;
using UnityAuthCore.Http;
using UnityEngine;

namespace UnityAuthCore.Backends
{
    /// <summary>
    /// Configurable relative endpoint paths used by <see cref="RestAuthBackendAdapter"/>.
    /// </summary>
    [Serializable]
    public sealed class RestEndpointMap
    {
        /// <summary>Relative path for guest sign-in (<c>POST</c>).</summary>
        public string guestPath = "/v1/auth/guest";
        /// <summary>Relative path for email/password registration (<c>POST</c>).</summary>
        public string registerPath = "/v1/auth/register";
        /// <summary>Relative path for email/password login (<c>POST</c>).</summary>
        public string loginPath = "/v1/auth/login";
        /// <summary>Relative path for refresh token rotation (<c>POST</c>).</summary>
        public string refreshPath = "/v1/auth/refresh";
        /// <summary>Relative path for server-side session logout (<c>POST</c>).</summary>
        public string logoutPath = "/v1/auth/logout";
        /// <summary>Relative path for reading (<c>GET</c>) and updating (<c>PATCH</c>) the active user's profile.</summary>
        public string profilePath = "/v1/account/me";
        /// <summary>Relative path for linking email/password credentials to a guest account (<c>POST</c>).</summary>
        public string linkEmailPath = "/v1/account/link";
        /// <summary>Relative path for dedicated-server token introspection (<c>POST</c>).</summary>
        public string introspectPath = "/v1/auth/introspect";
    }

    /// <summary>
    /// Backend-agnostic REST implementation of <see cref="IAuthBackendAdapter"/> matching <c>Docs~/openapi.yaml</c>.
    /// Developers can point BaseUrl at the Dockerized reference server, any custom ASP.NET/Node/Go/FastAPI backend,
    /// or override endpoint paths via <see cref="RestEndpointMap"/>.
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

        /// <inheritdoc/>
        public string ProviderId => "rest";

        /// <summary>
        /// Initializes a REST backend adapter targeting <paramref name="baseUrl"/>.
        /// </summary>
        /// <param name="http">HTTP client pipeline used to dispatch typed JSON requests.</param>
        /// <param name="baseUrl">Server base URL; trailing slashes are trimmed and defaults to <c>http://localhost:8080</c>.</param>
        /// <param name="endpoints">Optional path overrides; defaults to standard <c>/v1</c> paths.</param>
        /// <param name="clientApiKey">Optional key sent in the <c>X-Api-Key</c> header on every request.</param>
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

        /// <inheritdoc/>
        public Task<AuthResult<AuthSession>> SignInGuestAsync(string deviceId, string displayName = null, CancellationToken ct = default)
        {
            var req = CreateRequest("POST", _endpoints.guestPath, new GuestReq
            {
                deviceId = string.IsNullOrWhiteSpace(deviceId) ? SystemInfo.deviceUniqueIdentifier : deviceId,
                displayName = displayName ?? string.Empty
            }, requiresAuth: false);

            return _http.SendJsonAsync<AuthSession>(req, ct);
        }

        /// <inheritdoc/>
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

        /// <inheritdoc/>
        public Task<AuthResult<AuthSession>> LoginAsync(string email, string password, CancellationToken ct = default)
        {
            var req = CreateRequest("POST", _endpoints.loginPath, new LoginReq
            {
                email = email,
                password = password
            }, requiresAuth: false);

            return _http.SendJsonAsync<AuthSession>(req, ct);
        }

        /// <inheritdoc/>
        public Task<AuthResult<AuthSession>> RefreshAsync(string refreshToken, CancellationToken ct = default)
        {
            var req = CreateRequest("POST", _endpoints.refreshPath, new RefreshReq
            {
                refreshToken = refreshToken
            }, requiresAuth: false);
            // Never retry rotating refresh tokens automatically to avoid triggering reuse-detection revocation
            req.SkipRetry = true;
            return _http.SendJsonAsync<AuthSession>(req, ct);
        }

        /// <inheritdoc/>
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

        /// <inheritdoc/>
        public Task<AuthResult<AuthUserProfile>> GetProfileAsync(CancellationToken ct = default)
        {
            var req = CreateRequest("GET", _endpoints.profilePath, null, requiresAuth: true);
            return _http.SendJsonAsync<AuthUserProfile>(req, ct);
        }

        /// <inheritdoc/>
        public Task<AuthResult<AuthUserProfile>> UpdateProfileAsync(AuthProfileUpdateRequest update, CancellationToken ct = default)
        {
            var req = CreateRequest("PATCH", _endpoints.profilePath, update ?? new AuthProfileUpdateRequest(), requiresAuth: true);
            return _http.SendJsonAsync<AuthUserProfile>(req, ct);
        }

        /// <inheritdoc/>
        public Task<AuthResult<AuthSession>> LinkEmailPasswordAsync(string email, string password, CancellationToken ct = default)
        {
            var req = CreateRequest("POST", _endpoints.linkEmailPath, new LinkEmailReq
            {
                email = email,
                password = password
            }, requiresAuth: true);
            return _http.SendJsonAsync<AuthSession>(req, ct);
        }

        /// <inheritdoc/>
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

        /// <summary>
        /// Builds an <see cref="ApiRequest"/> with normalized path joining, JSON payload serialization, and optional <c>X-Api-Key</c>.
        /// </summary>
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
