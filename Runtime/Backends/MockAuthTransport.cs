using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;
using UnityAuthCore.Core;
using UnityAuthCore.Security;
using UnityEngine;

namespace UnityAuthCore.Backends
{
    /// <summary>
    /// Full in-process mock HTTP server implementing the UnityAuthCore OpenAPI v1 contract:
    /// HS256 JWT minting, rotating refresh tokens with reuse-detection family revocation,
    /// guest-to-email upgrade, token introspection, and fault injection for tests and Editor console.
    /// </summary>
    public sealed class MockAuthTransport : IHttpTransport
    {
        private sealed class MockAccount
        {
            public string AccountId;
            public string DeviceId;
            public string Email;
            public string Password;
            public string DisplayName;
            public string AvatarUrl;
            public string MetadataJson;
            public bool IsGuest;
            public List<string> Roles = new List<string> { "player" };
            public List<string> LinkedProviders = new List<string>();
        }

        private sealed class RefreshRecord
        {
            public string Token;
            public string FamilyId;
            public string AccountId;
            public bool Consumed;
            public bool Revoked;
            public long ExpiresAtUnix;
        }

        [Serializable] private sealed class GuestDto { public string deviceId; public string displayName; }
        [Serializable] private sealed class RegDto { public string email; public string password; public string displayName; }
        [Serializable] private sealed class LoginDto { public string email; public string password; }
        [Serializable] private sealed class RefreshDto { public string refreshToken; }
        [Serializable] private sealed class IntrospectDto { public string accessToken; }

        private readonly Dictionary<string, MockAccount> _accountsById = new Dictionary<string, MockAccount>(StringComparer.Ordinal);
        private readonly Dictionary<string, MockAccount> _accountsByEmail = new Dictionary<string, MockAccount>(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, MockAccount> _accountsByDevice = new Dictionary<string, MockAccount>(StringComparer.Ordinal);
        private readonly Dictionary<string, RefreshRecord> _refreshTokens = new Dictionary<string, RefreshRecord>(StringComparer.Ordinal);
        private readonly Func<DateTime> _utcNow;

        /// <summary>HS256 signing secret used to sign and verify mock access JWTs.</summary>
        public string JwtSecret { get; set; } = "dev-local-mock-secret-change-in-production-32bytes";
        /// <summary>JWT issuer (<c>iss</c>) embedded in issued mock tokens.</summary>
        public string Issuer { get; set; } = "unity-auth-core-mock";
        /// <summary>JWT audience (<c>aud</c>) embedded in issued mock tokens.</summary>
        public string Audience { get; set; } = "unity-game-client";
        /// <summary>Lifetime in seconds for minted access tokens (minimum effective value is 5 seconds).</summary>
        public int AccessTokenTtlSeconds { get; set; } = 300;
        /// <summary>Lifetime in seconds for minted refresh tokens (minimum effective value is 60 seconds).</summary>
        public int RefreshTokenTtlSeconds { get; set; } = 86400 * 7;
        /// <summary>Optional artificial delay in milliseconds applied before routing each request.</summary>
        public int SimulatedLatencyMs { get; set; } = 0;

        // Fault injection and telemetry counters for tests and Editor workbench
        /// <summary>Number of requests dispatched to <c>/v1/auth/refresh</c> since creation or the last <see cref="Reset"/>.</summary>
        public int RefreshEndpointHits { get; private set; }
        /// <summary>Total number of requests handled by <see cref="SendAsync"/> since creation or the last <see cref="Reset"/>.</summary>
        public int TotalRequestsHandled { get; private set; }
        /// <summary>When true, the next protected endpoint call returns HTTP 401 and resets this flag to false.</summary>
        public bool ForceNextProtectedCall401 { get; set; }
        /// <summary>Remaining number of incoming requests forced to return HTTP 429 with a 1-second <c>Retry-After</c> header.</summary>
        public int ForceNextRequests429Count { get; set; }

        /// <summary>
        /// Initializes a new in-process mock auth server transport.
        /// </summary>
        /// <param name="utcNowProvider">Optional UTC clock override for deterministic token expiry tests.</param>
        public MockAuthTransport(Func<DateTime> utcNowProvider = null)
        {
            _utcNow = utcNowProvider ?? (() => DateTime.UtcNow);
        }

        /// <summary>
        /// Clears all in-memory accounts, refresh token families, telemetry counters, and fault-injection flags.
        /// </summary>
        public void Reset()
        {
            _accountsById.Clear();
            _accountsByEmail.Clear();
            _accountsByDevice.Clear();
            _refreshTokens.Clear();
            RefreshEndpointHits = 0;
            TotalRequestsHandled = 0;
            ForceNextProtectedCall401 = false;
            ForceNextRequests429Count = 0;
        }

        /// <summary>
        /// Routes <paramref name="request"/> against the in-memory v1 auth endpoints and returns a simulated raw HTTP response.
        /// </summary>
        /// <param name="request">Outgoing API request descriptor.</param>
        /// <param name="ct">Optional cancellation token honored during <see cref="SimulatedLatencyMs"/>.</param>
        /// <returns>Simulated <see cref="HttpRawResponse"/> including <c>X-Request-Id</c> and measured duration.</returns>
        public async Task<HttpRawResponse> SendAsync(ApiRequest request, CancellationToken ct = default)
        {
            var sw = Stopwatch.StartNew();
            if (SimulatedLatencyMs > 0)
            {
                await Task.Delay(SimulatedLatencyMs, ct);
            }

            TotalRequestsHandled++;
            string path = ExtractPath(request.Url);
            string method = (request.Method ?? "GET").ToUpperInvariant();
            string reqId = request.Headers.TryGetValue("X-Request-Id", out string id) ? id : Guid.NewGuid().ToString("N");

            HttpRawResponse resp;

            if (ForceNextRequests429Count > 0)
            {
                ForceNextRequests429Count--;
                resp = ErrorResponse(429, "RATE_LIMITED", "Too many requests (simulated).", reqId, retryAfter: 1);
            }
            else if (method == "POST" && path.EndsWith("/v1/auth/guest", StringComparison.OrdinalIgnoreCase))
            {
                resp = HandleGuest(request.JsonBody, reqId);
            }
            else if (method == "POST" && path.EndsWith("/v1/auth/register", StringComparison.OrdinalIgnoreCase))
            {
                resp = HandleRegister(request.JsonBody, reqId);
            }
            else if (method == "POST" && path.EndsWith("/v1/auth/login", StringComparison.OrdinalIgnoreCase))
            {
                resp = HandleLogin(request.JsonBody, reqId);
            }
            else if (method == "POST" && path.EndsWith("/v1/auth/refresh", StringComparison.OrdinalIgnoreCase))
            {
                RefreshEndpointHits++;
                resp = HandleRefresh(request.JsonBody, reqId);
            }
            else if (method == "POST" && path.EndsWith("/v1/auth/logout", StringComparison.OrdinalIgnoreCase))
            {
                resp = HandleLogout(request.JsonBody, reqId);
            }
            else if (method == "POST" && path.EndsWith("/v1/auth/introspect", StringComparison.OrdinalIgnoreCase))
            {
                resp = HandleIntrospect(request.JsonBody, reqId);
            }
            else if (path.EndsWith("/v1/account/me", StringComparison.OrdinalIgnoreCase))
            {
                resp = method == "PATCH"
                    ? HandleUpdateProfile(request, reqId)
                    : HandleGetProfile(request, reqId);
            }
            else if (method == "POST" && path.EndsWith("/v1/account/link", StringComparison.OrdinalIgnoreCase))
            {
                resp = HandleLinkEmail(request, reqId);
            }
            else
            {
                resp = ErrorResponse(404, "NOT_FOUND", $"Mock route not found: {method} {path}", reqId);
            }

            sw.Stop();
            resp.DurationMs = sw.Elapsed.TotalMilliseconds;
            resp.Headers["X-Request-Id"] = reqId;
            return resp;
        }

        /// <summary>
        /// Handles <c>POST /v1/auth/guest</c>, creating or reusing a guest account keyed by device ID.
        /// </summary>
        private HttpRawResponse HandleGuest(string body, string reqId)
        {
            var dto = JsonUtility.FromJson<GuestDto>(body ?? "{}");
            string deviceId = string.IsNullOrWhiteSpace(dto.deviceId) ? Guid.NewGuid().ToString("N") : dto.deviceId;

            if (!_accountsByDevice.TryGetValue(deviceId, out MockAccount acc))
            {
                string id = "acc_" + Guid.NewGuid().ToString("N").Substring(0, 12);
                acc = new MockAccount
                {
                    AccountId = id,
                    DeviceId = deviceId,
                    DisplayName = string.IsNullOrWhiteSpace(dto.displayName) ? $"Guest_{id.Substring(4, 6)}" : dto.displayName,
                    IsGuest = true,
                    LinkedProviders = new List<string> { "guest" }
                };
                _accountsById[id] = acc;
                _accountsByDevice[deviceId] = acc;
            }

            return JsonResponse(200, IssueSession(acc, familyId: null));
        }

        /// <summary>
        /// Handles <c>POST /v1/auth/register</c>, validating email/password constraints and returning 201 or 409 on conflict.
        /// </summary>
        private HttpRawResponse HandleRegister(string body, string reqId)
        {
            var dto = JsonUtility.FromJson<RegDto>(body ?? "{}");
            if (string.IsNullOrWhiteSpace(dto.email) || !dto.email.Contains("@"))
            {
                return ErrorResponse(400, "VALIDATION_ERROR", "A valid email address is required.", reqId);
            }
            if (string.IsNullOrWhiteSpace(dto.password) || dto.password.Length < 6)
            {
                return ErrorResponse(400, "VALIDATION_ERROR", "Password must be at least 6 characters.", reqId);
            }
            if (_accountsByEmail.ContainsKey(dto.email))
            {
                return ErrorResponse(409, "EMAIL_ALREADY_EXISTS", "An account with this email already exists.", reqId);
            }

            string id = "acc_" + Guid.NewGuid().ToString("N").Substring(0, 12);
            var acc = new MockAccount
            {
                AccountId = id,
                Email = dto.email.Trim(),
                Password = dto.password,
                DisplayName = string.IsNullOrWhiteSpace(dto.displayName) ? dto.email.Split('@')[0] : dto.displayName.Trim(),
                IsGuest = false,
                LinkedProviders = new List<string> { "email" }
            };
            _accountsById[id] = acc;
            _accountsByEmail[acc.Email] = acc;

            return JsonResponse(201, IssueSession(acc, familyId: null));
        }

        /// <summary>
        /// Handles <c>POST /v1/auth/login</c>, verifying email and password credentials against stored mock accounts.
        /// </summary>
        private HttpRawResponse HandleLogin(string body, string reqId)
        {
            var dto = JsonUtility.FromJson<LoginDto>(body ?? "{}");
            if (string.IsNullOrWhiteSpace(dto.email) ||
                !_accountsByEmail.TryGetValue(dto.email.Trim(), out MockAccount acc) ||
                !string.Equals(acc.Password, dto.password, StringComparison.Ordinal))
            {
                return ErrorResponse(401, "INVALID_CREDENTIALS", "Invalid email or password.", reqId);
            }

            return JsonResponse(200, IssueSession(acc, familyId: null));
        }

        /// <summary>
        /// Handles <c>POST /v1/auth/refresh</c>, rotating the refresh token within its family and revoking the entire family on replay.
        /// </summary>
        private HttpRawResponse HandleRefresh(string body, string reqId)
        {
            var dto = JsonUtility.FromJson<RefreshDto>(body ?? "{}");
            if (string.IsNullOrWhiteSpace(dto.refreshToken) ||
                !_refreshTokens.TryGetValue(dto.refreshToken, out RefreshRecord rec))
            {
                return ErrorResponse(401, "INVALID_REFRESH_TOKEN", "Refresh token is unknown.", reqId);
            }

            long now = NowUnix();
            if (rec.Revoked || rec.ExpiresAtUnix <= now)
            {
                return ErrorResponse(401, "REFRESH_TOKEN_REVOKED", "Refresh token is revoked or expired.", reqId);
            }

            // Refresh token reuse detection: replaying an already-consumed token revokes the entire family
            if (rec.Consumed)
            {
                RevokeFamily(rec.FamilyId);
                return ErrorResponse(401, "REFRESH_TOKEN_REUSE_DETECTED", "Refresh token reuse detected. Session family revoked.", reqId);
            }

            rec.Consumed = true;
            if (!_accountsById.TryGetValue(rec.AccountId, out MockAccount acc))
            {
                return ErrorResponse(401, "ACCOUNT_NOT_FOUND", "Account no longer exists.", reqId);
            }

            return JsonResponse(200, IssueSession(acc, familyId: rec.FamilyId));
        }

        /// <summary>
        /// Handles <c>POST /v1/auth/logout</c>, revoking the refresh token's session family if present and returning 204.
        /// </summary>
        private HttpRawResponse HandleLogout(string body, string reqId)
        {
            var dto = JsonUtility.FromJson<RefreshDto>(body ?? "{}");
            if (!string.IsNullOrWhiteSpace(dto.refreshToken) &&
                _refreshTokens.TryGetValue(dto.refreshToken, out RefreshRecord rec))
            {
                RevokeFamily(rec.FamilyId);
            }
            return new HttpRawResponse { StatusCode = 204, Body = string.Empty };
        }

        /// <summary>
        /// Handles <c>POST /v1/auth/introspect</c>, verifying the supplied access token with <see cref="JwtUtility.VerifyHs256"/>.
        /// </summary>
        private HttpRawResponse HandleIntrospect(string body, string reqId)
        {
            var dto = JsonUtility.FromJson<IntrospectDto>(body ?? "{}");
            var val = JwtUtility.VerifyHs256(dto.accessToken, JwtSecret, Issuer, Audience, clockSkewSeconds: 0, utcNow: _utcNow());
            return JsonResponse(200, val);
        }

        /// <summary>
        /// Handles <c>GET /v1/account/me</c> for an authenticated bearer session.
        /// </summary>
        private HttpRawResponse HandleGetProfile(ApiRequest req, string reqId)
        {
            if (!TryAuthenticateBearer(req, reqId, out MockAccount acc, out HttpRawResponse err))
            {
                return err;
            }
            return JsonResponse(200, ToProfile(acc));
        }

        /// <summary>
        /// Handles <c>PATCH /v1/account/me</c>, mutating non-null profile fields on the authenticated mock account.
        /// </summary>
        private HttpRawResponse HandleUpdateProfile(ApiRequest req, string reqId)
        {
            if (!TryAuthenticateBearer(req, reqId, out MockAccount acc, out HttpRawResponse err))
            {
                return err;
            }

            var update = JsonUtility.FromJson<AuthProfileUpdateRequest>(req.JsonBody ?? "{}");
            if (!string.IsNullOrWhiteSpace(update.displayName)) acc.DisplayName = update.displayName.Trim();
            if (update.avatarUrl != null) acc.AvatarUrl = update.avatarUrl;
            if (update.metadataJson != null) acc.MetadataJson = update.metadataJson;

            return JsonResponse(200, ToProfile(acc));
        }

        /// <summary>
        /// Handles <c>POST /v1/account/link</c>, upgrading a guest account to an email/password account and minting a fresh session.
        /// </summary>
        private HttpRawResponse HandleLinkEmail(ApiRequest req, string reqId)
        {
            if (!TryAuthenticateBearer(req, reqId, out MockAccount acc, out HttpRawResponse err))
            {
                return err;
            }

            var dto = JsonUtility.FromJson<LoginDto>(req.JsonBody ?? "{}");
            if (string.IsNullOrWhiteSpace(dto.email) || !dto.email.Contains("@") || string.IsNullOrWhiteSpace(dto.password) || dto.password.Length < 6)
            {
                return ErrorResponse(400, "VALIDATION_ERROR", "Valid email and password (min 6 chars) required.", reqId);
            }

            if (_accountsByEmail.ContainsKey(dto.email.Trim()))
            {
                return ErrorResponse(409, "EMAIL_ALREADY_EXISTS", "Email is already linked to another account.", reqId);
            }

            acc.Email = dto.email.Trim();
            acc.Password = dto.password;
            acc.IsGuest = false;
            if (!acc.LinkedProviders.Contains("email")) acc.LinkedProviders.Add("email");
            _accountsByEmail[acc.Email] = acc;

            return JsonResponse(200, IssueSession(acc, familyId: null));
        }

        /// <summary>
        /// Validates the request's <c>Authorization: Bearer</c> JWT and resolves the owning <see cref="MockAccount"/>.
        /// </summary>
        private bool TryAuthenticateBearer(ApiRequest req, string reqId, out MockAccount account, out HttpRawResponse error)
        {
            account = null;
            error = null;

            if (ForceNextProtectedCall401)
            {
                ForceNextProtectedCall401 = false;
                error = ErrorResponse(401, "TOKEN_EXPIRED", "Simulated 401 unauthorized response.", reqId);
                return false;
            }

            if (!req.Headers.TryGetValue("Authorization", out string auth) ||
                string.IsNullOrWhiteSpace(auth) ||
                !auth.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
            {
                error = ErrorResponse(401, "MISSING_BEARER", "Authorization Bearer token is required.", reqId);
                return false;
            }

            string token = auth.Substring("Bearer ".Length).Trim();
            var verified = JwtUtility.VerifyHs256(token, JwtSecret, Issuer, Audience, clockSkewSeconds: 0, utcNow: _utcNow());
            if (!verified.isValid)
            {
                error = ErrorResponse(401, verified.failureCode, verified.failureReason, reqId);
                return false;
            }

            if (!_accountsById.TryGetValue(verified.accountId, out account))
            {
                error = ErrorResponse(401, "ACCOUNT_NOT_FOUND", "Account not found.", reqId);
                return false;
            }

            return true;
        }

        /// <summary>
        /// Mints a new HS256 access token and refresh token record under <paramref name="familyId"/> (or a new family when null).
        /// </summary>
        private AuthSession IssueSession(MockAccount acc, string familyId)
        {
            long now = NowUnix();
            long accessExp = now + Math.Max(5, AccessTokenTtlSeconds);
            long refreshExp = now + Math.Max(60, RefreshTokenTtlSeconds);

            var claims = new JwtClaims
            {
                sub = acc.AccountId,
                iss = Issuer,
                aud = Audience,
                email = acc.Email,
                displayName = acc.DisplayName,
                isGuest = acc.IsGuest,
                roles = new List<string>(acc.Roles),
                iat = now,
                exp = accessExp
            };

            string jwt = JwtUtility.CreateHs256Token(claims, JwtSecret);
            string refresh = "rt_" + Guid.NewGuid().ToString("N") + Guid.NewGuid().ToString("N").Substring(0, 8);
            string fam = string.IsNullOrEmpty(familyId) ? "fam_" + Guid.NewGuid().ToString("N").Substring(0, 10) : familyId;

            _refreshTokens[refresh] = new RefreshRecord
            {
                Token = refresh,
                FamilyId = fam,
                AccountId = acc.AccountId,
                Consumed = false,
                Revoked = false,
                ExpiresAtUnix = refreshExp
            };

            return new AuthSession
            {
                accessToken = jwt,
                refreshToken = refresh,
                tokenType = "Bearer",
                expiresAtUnixSeconds = accessExp,
                providerId = "mock",
                user = ToProfile(acc)
            };
        }

        /// <summary>
        /// Marks every refresh token belonging to <paramref name="familyId"/> as revoked.
        /// </summary>
        private void RevokeFamily(string familyId)
        {
            foreach (var kvp in _refreshTokens)
            {
                if (string.Equals(kvp.Value.FamilyId, familyId, StringComparison.Ordinal))
                {
                    kvp.Value.Revoked = true;
                }
            }
        }

        /// <summary>
        /// Maps an internal <see cref="MockAccount"/> record to a public <see cref="AuthUserProfile"/> copy.
        /// </summary>
        private static AuthUserProfile ToProfile(MockAccount acc)
        {
            return new AuthUserProfile
            {
                accountId = acc.AccountId,
                displayName = acc.DisplayName,
                email = acc.Email ?? string.Empty,
                avatarUrl = acc.AvatarUrl ?? string.Empty,
                isGuest = acc.IsGuest,
                roles = new List<string>(acc.Roles),
                linkedProviders = new List<string>(acc.LinkedProviders),
                metadataJson = acc.MetadataJson ?? string.Empty
            };
        }

        private long NowUnix() => new DateTimeOffset(_utcNow()).ToUnixTimeSeconds();

        /// <summary>
        /// Extracts the path portion from an absolute or relative request URL for route matching.
        /// </summary>
        private static string ExtractPath(string url)
        {
            if (string.IsNullOrWhiteSpace(url)) return "/";
            if (Uri.TryCreate(url, UriKind.Absolute, out Uri uri)) return uri.AbsolutePath;
            return url;
        }

        private static HttpRawResponse JsonResponse(int status, object payload)
        {
            return new HttpRawResponse
            {
                StatusCode = status,
                Body = JsonUtility.ToJson(payload)
            };
        }

        /// <summary>
        /// Serializes an <see cref="ApiError"/> payload into an <see cref="HttpRawResponse"/>, setting <c>Retry-After</c> when positive.
        /// </summary>
        private static HttpRawResponse ErrorResponse(int status, string code, string message, string reqId, int retryAfter = 0)
        {
            var err = ApiError.Create(status, code, message, reqId, retryAfter);
            var resp = new HttpRawResponse
            {
                StatusCode = status,
                Body = JsonUtility.ToJson(err)
            };
            if (retryAfter > 0) resp.Headers["Retry-After"] = retryAfter.ToString();
            return resp;
        }
    }
}
