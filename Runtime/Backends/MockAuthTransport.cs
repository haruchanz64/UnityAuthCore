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

        public string JwtSecret { get; set; } = "dev-local-mock-secret-change-in-production-32bytes";
        public string Issuer { get; set; } = "unity-auth-core-mock";
        public string Audience { get; set; } = "unity-game-client";
        public int AccessTokenTtlSeconds { get; set; } = 300;
        public int RefreshTokenTtlSeconds { get; set; } = 86400 * 7;
        public int SimulatedLatencyMs { get; set; } = 0;

        // Fault injection & telemetry counters for tests and Editor workbench
        public int RefreshEndpointHits { get; private set; }
        public int TotalRequestsHandled { get; private set; }
        public bool ForceNextProtectedCall401 { get; set; }
        public int ForceNextRequests429Count { get; set; }

        public MockAuthTransport(Func<DateTime> utcNowProvider = null)
        {
            _utcNow = utcNowProvider ?? (() => DateTime.UtcNow);
        }

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

            // Refresh token reuse detection: replaying an already-consumed token revokes the entire family!
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

        private HttpRawResponse HandleIntrospect(string body, string reqId)
        {
            var dto = JsonUtility.FromJson<IntrospectDto>(body ?? "{}");
            var val = JwtUtility.VerifyHs256(dto.accessToken, JwtSecret, Issuer, Audience, clockSkewSeconds: 0, utcNow: _utcNow());
            return JsonResponse(200, val);
        }

        private HttpRawResponse HandleGetProfile(ApiRequest req, string reqId)
        {
            if (!TryAuthenticateBearer(req, reqId, out MockAccount acc, out HttpRawResponse err))
            {
                return err;
            }
            return JsonResponse(200, ToProfile(acc));
        }

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
