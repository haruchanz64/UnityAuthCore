using System;
using System.Collections.Generic;
using UnityEngine;

namespace UnityAuthCore.Core
{
    /// <summary>
    /// Selects which backend execution path <see cref="UnityAuthCore.Config.AuthFrameworkConfig"/> creates.
    /// </summary>
    public enum AuthBackendMode
    {
        /// <summary>Uses the in-process <see cref="UnityAuthCore.Backends.MockAuthTransport"/> with no network calls.</summary>
        MockInProcess = 0,
        /// <summary>Connects over HTTP/HTTPS to a REST backend matching the OpenAPI v1 contract.</summary>
        RestEndpoint = 1,
        /// <summary>Defers backend calls to a caller-supplied <see cref="IAuthBackendAdapter"/>.</summary>
        CustomAdapter = 2
    }

    /// <summary>
    /// Selects how <see cref="AuthSession"/> tokens are persisted across application restarts.
    /// </summary>
    public enum TokenStorageMode
    {
        /// <summary>Keeps session tokens in RAM only; sessions are lost when the process exits.</summary>
        InMemory = 0,
        /// <summary>Persists session tokens to disk encrypted with AES-256-CBC and HMAC-SHA256.</summary>
        EncryptedFile = 1
    }

    /// <summary>
    /// Profile data returned for an authenticated player account.
    /// </summary>
    [Serializable]
    public sealed class AuthUserProfile
    {
        /// <summary>Unique server-assigned account identifier.</summary>
        public string accountId;
        /// <summary>Player-facing display name.</summary>
        public string displayName;
        /// <summary>Linked email address, or empty for unlinked guest accounts.</summary>
        public string email;
        /// <summary>Optional URL pointing to the player's avatar image.</summary>
        public string avatarUrl;
        /// <summary>True when the account has not been upgraded with permanent credentials.</summary>
        public bool isGuest;
        /// <summary>Authorization roles granted to the account (for example, <c>player</c> or <c>admin</c>).</summary>
        public List<string> roles = new List<string>();
        /// <summary>Identity providers currently linked to the account (for example, <c>guest</c> or <c>email</c>).</summary>
        public List<string> linkedProviders = new List<string>();
        /// <summary>Optional serialized JSON string containing game-specific profile metadata.</summary>
        public string metadataJson;
    }

    /// <summary>
    /// Represents an active authentication session including access/refresh tokens and user profile data.
    /// </summary>
    [Serializable]
    public sealed class AuthSession
    {
        /// <summary>Short-lived bearer access token (typically a JWT) sent on protected API requests.</summary>
        public string accessToken;
        /// <summary>Long-lived refresh token used to obtain rotated session credentials.</summary>
        public string refreshToken;
        /// <summary>HTTP authorization scheme name, typically <c>Bearer</c>.</summary>
        public string tokenType = "Bearer";
        /// <summary>Access token expiration timestamp in Unix epoch seconds (UTC).</summary>
        public long expiresAtUnixSeconds;
        /// <summary>Identifier of the <see cref="IAuthBackendAdapter"/> that issued this session.</summary>
        public string providerId = "rest";
        /// <summary>User profile associated with the authenticated account.</summary>
        public AuthUserProfile user = new AuthUserProfile();

        /// <summary>True when <see cref="accessToken"/> contains a non-whitespace value.</summary>
        public bool HasAccessToken => !string.IsNullOrWhiteSpace(accessToken);
        /// <summary>True when <see cref="refreshToken"/> contains a non-whitespace value.</summary>
        public bool HasRefreshToken => !string.IsNullOrWhiteSpace(refreshToken);

        /// <summary>
        /// Checks whether the access token is missing or expires within the specified skew window.
        /// </summary>
        /// <param name="skewSeconds">Proactive safety margin in seconds; negative values are clamped to 0.</param>
        /// <param name="utcNow">Optional UTC clock override for deterministic tests; defaults to <see cref="DateTime.UtcNow"/>.</param>
        /// <returns>True if the access token is missing or at/past its effective expiry time.</returns>
        public bool IsAccessTokenExpired(int skewSeconds = 30, DateTime? utcNow = null)
        {
            if (!HasAccessToken) return true;
            long now = new DateTimeOffset(utcNow ?? DateTime.UtcNow).ToUnixTimeSeconds();
            return expiresAtUnixSeconds <= now + Math.Max(0, skewSeconds);
        }

        /// <summary>
        /// Returns the number of whole seconds remaining until <see cref="expiresAtUnixSeconds"/>.
        /// </summary>
        /// <param name="utcNow">Optional UTC clock override for deterministic tests; defaults to <see cref="DateTime.UtcNow"/>.</param>
        /// <returns>Remaining lifetime in seconds, clamped to a minimum of 0.</returns>
        public long GetRemainingSeconds(DateTime? utcNow = null)
        {
            long now = new DateTimeOffset(utcNow ?? DateTime.UtcNow).ToUnixTimeSeconds();
            return Math.Max(0, expiresAtUnixSeconds - now);
        }

        /// <summary>
        /// Creates a deep copy of this session via <see cref="JsonUtility"/> serialization.
        /// </summary>
        /// <returns>An independent <see cref="AuthSession"/> instance with copied fields and lists.</returns>
        public AuthSession Clone()
        {
            string json = JsonUtility.ToJson(this);
            return JsonUtility.FromJson<AuthSession>(json);
        }
    }

    /// <summary>
    /// Decoded JWT header and payload claims produced by <see cref="UnityAuthCore.Security.JwtUtility"/>.
    /// </summary>
    [Serializable]
    public sealed class JwtClaims
    {
        /// <summary>Subject claim (<c>sub</c>), typically the account ID.</summary>
        public string sub;
        /// <summary>Issuer claim (<c>iss</c>) identifying the token authority.</summary>
        public string iss;
        /// <summary>Audience claim (<c>aud</c>) identifying the intended recipient.</summary>
        public string aud;
        /// <summary>Optional email address claim embedded in the token.</summary>
        public string email;
        /// <summary>Optional display name claim embedded in the token.</summary>
        public string displayName;
        /// <summary>True if the token represents a guest account.</summary>
        public bool isGuest;
        /// <summary>Unique JWT identifier (<c>jti</c>) for replay tracking or logging.</summary>
        public string jti;
        /// <summary>Issued-at timestamp (<c>iat</c>) in Unix epoch seconds.</summary>
        public long iat;
        /// <summary>Expiration timestamp (<c>exp</c>) in Unix epoch seconds.</summary>
        public long exp;
        /// <summary>Roles granted to the subject.</summary>
        public List<string> roles = new List<string>();
        /// <summary>Raw UTF-8 JSON string decoded from the JWT header segment.</summary>
        public string rawHeaderJson;
        /// <summary>Raw UTF-8 JSON string decoded from the JWT payload segment.</summary>
        public string rawPayloadJson;

        /// <summary>
        /// Checks whether the token's <see cref="exp"/> claim has passed.
        /// </summary>
        /// <param name="skewSeconds">Proactive safety margin in seconds; negative values are clamped to 0.</param>
        /// <param name="utcNow">Optional UTC clock override; defaults to <see cref="DateTime.UtcNow"/>.</param>
        /// <returns>False when <see cref="exp"/> is 0 or negative; otherwise true when expired within the skew window.</returns>
        public bool IsExpired(int skewSeconds = 0, DateTime? utcNow = null)
        {
            if (exp <= 0) return false;
            long now = new DateTimeOffset(utcNow ?? DateTime.UtcNow).ToUnixTimeSeconds();
            return exp <= now + Math.Max(0, skewSeconds);
        }
    }

    /// <summary>
    /// Field-level validation error entry returned inside <see cref="ApiError.fieldErrors"/>.
    /// </summary>
    [Serializable]
    public sealed class ApiFieldError
    {
        /// <summary>Name of the invalid request field.</summary>
        public string field;
        /// <summary>Human-readable reason why the field failed validation.</summary>
        public string reason;
    }

    /// <summary>
    /// Structured error envelope parsed from failed HTTP responses or generated locally for transport failures.
    /// </summary>
    [Serializable]
    public sealed class ApiError
    {
        /// <summary>HTTP status code associated with the error, or 0 for local/network errors.</summary>
        public int statusCode;
        /// <summary>Machine-readable error code (for example, <c>INVALID_CREDENTIALS</c> or <c>RATE_LIMITED</c>).</summary>
        public string errorCode;
        /// <summary>Human-readable description of the failure.</summary>
        public string message;
        /// <summary>Correlation identifier from the <c>X-Request-Id</c> header, if available.</summary>
        public string requestId;
        /// <summary>Suggested retry delay in seconds parsed from a <c>Retry-After</c> header or error payload.</summary>
        public int retryAfterSeconds;
        /// <summary>Optional list of per-field validation errors.</summary>
        public List<ApiFieldError> fieldErrors = new List<ApiFieldError>();

        /// <summary>
        /// Creates a populated <see cref="ApiError"/> with safe non-null fallback defaults.
        /// </summary>
        /// <param name="status">HTTP status code (or 0 for transport errors).</param>
        /// <param name="code">Machine-readable error code; defaults to <c>UNKNOWN_ERROR</c> if null.</param>
        /// <param name="msg">Human-readable failure message; defaults to <c>Request failed.</c> if null.</param>
        /// <param name="reqId">Optional request correlation ID.</param>
        /// <param name="retryAfter">Optional retry wait duration in seconds.</param>
        /// <returns>A new <see cref="ApiError"/> instance.</returns>
        public static ApiError Create(int status, string code, string msg, string reqId = null, int retryAfter = 0)
        {
            return new ApiError
            {
                statusCode = status,
                errorCode = code ?? "UNKNOWN_ERROR",
                message = msg ?? "Request failed.",
                requestId = reqId ?? string.Empty,
                retryAfterSeconds = retryAfter
            };
        }
    }

    /// <summary>
    /// Outcome wrapper returned by authentication and API operations without throwing on HTTP errors.
    /// </summary>
    /// <typeparam name="T">Type of the deserialized success payload.</typeparam>
    public sealed class AuthResult<T>
    {
        /// <summary>True when the operation completed with a 2xx response and valid payload.</summary>
        public bool Succeeded { get; private set; }
        /// <summary>Deserialized payload when <see cref="Succeeded"/> is true; otherwise default.</summary>
        public T Data { get; private set; }
        /// <summary>Structured failure details when <see cref="Succeeded"/> is false; otherwise null.</summary>
        public ApiError Error { get; private set; }
        /// <summary>HTTP status code returned by the transport, or 0 for local/network failures.</summary>
        public int StatusCode { get; private set; }

        /// <summary>
        /// Creates a successful <see cref="AuthResult{T}"/> carrying <paramref name="data"/>.
        /// </summary>
        /// <param name="data">Operation result payload.</param>
        /// <param name="statusCode">HTTP status code (defaults to 200).</param>
        /// <returns>A succeeded <see cref="AuthResult{T}"/>.</returns>
        public static AuthResult<T> Ok(T data, int statusCode = 200)
        {
            return new AuthResult<T>
            {
                Succeeded = true,
                Data = data,
                StatusCode = statusCode
            };
        }

        /// <summary>
        /// Creates a failed <see cref="AuthResult{T}"/> carrying <paramref name="error"/>.
        /// </summary>
        /// <param name="error">Error details; falls back to an <c>UNKNOWN_ERROR</c> envelope when null.</param>
        /// <returns>A failed <see cref="AuthResult{T}"/>.</returns>
        public static AuthResult<T> Fail(ApiError error)
        {
            return new AuthResult<T>
            {
                Succeeded = false,
                Error = error ?? ApiError.Create(0, "UNKNOWN_ERROR", "Unknown auth failure."),
                StatusCode = error != null ? error.statusCode : 0
            };
        }
    }

    /// <summary>
    /// Mutable HTTP request descriptor passed through interceptors and sent by an <see cref="IHttpTransport"/>.
    /// </summary>
    public sealed class ApiRequest
    {
        /// <summary>HTTP verb such as <c>GET</c>, <c>POST</c>, <c>PATCH</c>, or <c>PUT</c>.</summary>
        public string Method { get; set; } = "GET";
        /// <summary>Full target request URL.</summary>
        public string Url { get; set; }
        /// <summary>Optional UTF-8 JSON request body, or null for bodyless requests.</summary>
        public string JsonBody { get; set; }
        /// <summary>Case-insensitive HTTP headers sent with the request.</summary>
        public Dictionary<string, string> Headers { get; } = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        /// <summary>When true, <see cref="UnityAuthCore.Http.BearerAuthInterceptor"/> attaches the current Bearer token and 401 responses trigger single-flight refresh.</summary>
        public bool RequiresAuth { get; set; }
        /// <summary>When true, <see cref="IRetryPolicy"/> implementations should not retry transient failures on this request.</summary>
        public bool SkipRetry { get; set; }
        /// <summary>Per-request transport timeout in seconds (defaults to 15).</summary>
        public int TimeoutSeconds { get; set; } = 15;
    }

    /// <summary>
    /// Low-level HTTP response returned by an <see cref="IHttpTransport"/> implementation.
    /// </summary>
    public sealed class HttpRawResponse
    {
        /// <summary>HTTP status code received from the server, or 0 if no HTTP response arrived.</summary>
        public int StatusCode { get; set; }
        /// <summary>True when the transport failed due to a connection, timeout, or data-processing error.</summary>
        public bool IsNetworkError { get; set; }
        /// <summary>Raw response body text.</summary>
        public string Body { get; set; }
        /// <summary>Transport-level error text when <see cref="IsNetworkError"/> or protocol failure occurs.</summary>
        public string ErrorText { get; set; }
        /// <summary>Case-insensitive response headers returned by the server.</summary>
        public Dictionary<string, string> Headers { get; } = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        /// <summary>Measured round-trip duration in milliseconds.</summary>
        public double DurationMs { get; set; }

        /// <summary>True when there was no network error and <see cref="StatusCode"/> is in the 200 to 299 range.</summary>
        public bool IsSuccess => !IsNetworkError && StatusCode >= 200 && StatusCode < 300;
    }

    /// <summary>
    /// Diagnostic snapshot of a completed HTTP request recorded by <see cref="UnityAuthCore.Http.ApiHttpClient"/>.
    /// </summary>
    [Serializable]
    public sealed class ApiTraceEntry
    {
        /// <summary>ISO-8601 UTC timestamp when the trace entry was recorded.</summary>
        public string timestampUtc;
        /// <summary>Correlation ID from <c>X-Request-Id</c>, if present.</summary>
        public string requestId;
        /// <summary>HTTP method used for the request.</summary>
        public string method;
        /// <summary>Target URL requested.</summary>
        public string url;
        /// <summary>HTTP status code received.</summary>
        public int statusCode;
        /// <summary>Measured round-trip duration in milliseconds.</summary>
        public double durationMs;
        /// <summary>True if the response had a 2xx status without a network error.</summary>
        public bool succeeded;
        /// <summary>True if this attempt was a retry or a post-refresh replay.</summary>
        public bool wasRetried;
        /// <summary>Truncated and password-redacted preview of the request body.</summary>
        public string requestBodyPreview;
        /// <summary>Truncated preview of the response body.</summary>
        public string responseBodyPreview;
    }

    /// <summary>
    /// Server-side token validation outcome returned by <see cref="IServerTokenValidator"/> and token introspection endpoints.
    /// </summary>
    [Serializable]
    public sealed class TokenValidationResult
    {
        /// <summary>True when the token passed signature, expiry, issuer, and audience validation.</summary>
        public bool isValid;
        /// <summary>Verified account ID extracted from the token when <see cref="isValid"/> is true.</summary>
        public string accountId;
        /// <summary>Verified player display name when available.</summary>
        public string displayName;
        /// <summary>True if the verified account is a guest account.</summary>
        public bool isGuest;
        /// <summary>Roles granted to the verified account.</summary>
        public List<string> roles = new List<string>();
        /// <summary>Token expiration time in Unix epoch seconds.</summary>
        public long expiresAtUnixSeconds;
        /// <summary>Machine-readable failure code when <see cref="isValid"/> is false.</summary>
        public string failureCode;
        /// <summary>Human-readable rejection reason when <see cref="isValid"/> is false.</summary>
        public string failureReason;
    }

    /// <summary>
    /// Partial profile update payload sent to <see cref="IAuthBackendAdapter.UpdateProfileAsync"/>.
    /// </summary>
    [Serializable]
    public sealed class AuthProfileUpdateRequest
    {
        /// <summary>New display name to assign; null or whitespace leaves the existing value unchanged on reference servers.</summary>
        public string displayName;
        /// <summary>New avatar URL to store, or null to omit updating.</summary>
        public string avatarUrl;
        /// <summary>New serialized JSON metadata string to store, or null to omit updating.</summary>
        public string metadataJson;
    }
}
