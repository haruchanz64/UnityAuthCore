using System;
using System.Collections.Generic;
using UnityEngine;

namespace UnityAuthCore.Core
{
    public enum AuthBackendMode
    {
        MockInProcess = 0,
        RestEndpoint = 1,
        CustomAdapter = 2
    }

    public enum TokenStorageMode
    {
        InMemory = 0,
        EncryptedFile = 1
    }

    [Serializable]
    public sealed class AuthUserProfile
    {
        public string accountId;
        public string displayName;
        public string email;
        public string avatarUrl;
        public bool isGuest;
        public List<string> roles = new List<string>();
        public List<string> linkedProviders = new List<string>();
        public string metadataJson;
    }

    [Serializable]
    public sealed class AuthSession
    {
        public string accessToken;
        public string refreshToken;
        public string tokenType = "Bearer";
        public long expiresAtUnixSeconds;
        public string providerId = "rest";
        public AuthUserProfile user = new AuthUserProfile();

        public bool HasAccessToken => !string.IsNullOrWhiteSpace(accessToken);
        public bool HasRefreshToken => !string.IsNullOrWhiteSpace(refreshToken);

        public bool IsAccessTokenExpired(int skewSeconds = 30, DateTime? utcNow = null)
        {
            if (!HasAccessToken) return true;
            long now = new DateTimeOffset(utcNow ?? DateTime.UtcNow).ToUnixTimeSeconds();
            return expiresAtUnixSeconds <= now + Math.Max(0, skewSeconds);
        }

        public long GetRemainingSeconds(DateTime? utcNow = null)
        {
            long now = new DateTimeOffset(utcNow ?? DateTime.UtcNow).ToUnixTimeSeconds();
            return Math.Max(0, expiresAtUnixSeconds - now);
        }

        public AuthSession Clone()
        {
            string json = JsonUtility.ToJson(this);
            return JsonUtility.FromJson<AuthSession>(json);
        }
    }

    [Serializable]
    public sealed class JwtClaims
    {
        public string sub;
        public string iss;
        public string aud;
        public string email;
        public string displayName;
        public bool isGuest;
        public string jti;
        public long iat;
        public long exp;
        public List<string> roles = new List<string>();
        public string rawHeaderJson;
        public string rawPayloadJson;

        public bool IsExpired(int skewSeconds = 0, DateTime? utcNow = null)
        {
            if (exp <= 0) return false;
            long now = new DateTimeOffset(utcNow ?? DateTime.UtcNow).ToUnixTimeSeconds();
            return exp <= now + Math.Max(0, skewSeconds);
        }
    }

    [Serializable]
    public sealed class ApiFieldError
    {
        public string field;
        public string reason;
    }

    [Serializable]
    public sealed class ApiError
    {
        public int statusCode;
        public string errorCode;
        public string message;
        public string requestId;
        public int retryAfterSeconds;
        public List<ApiFieldError> fieldErrors = new List<ApiFieldError>();

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

    public sealed class AuthResult<T>
    {
        public bool Succeeded { get; private set; }
        public T Data { get; private set; }
        public ApiError Error { get; private set; }
        public int StatusCode { get; private set; }

        public static AuthResult<T> Ok(T data, int statusCode = 200)
        {
            return new AuthResult<T>
            {
                Succeeded = true,
                Data = data,
                StatusCode = statusCode
            };
        }

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

    public sealed class ApiRequest
    {
        public string Method { get; set; } = "GET";
        public string Url { get; set; }
        public string JsonBody { get; set; }
        public Dictionary<string, string> Headers { get; } = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        public bool RequiresAuth { get; set; }
        public bool SkipRetry { get; set; }
        public int TimeoutSeconds { get; set; } = 15;
    }

    public sealed class HttpRawResponse
    {
        public int StatusCode { get; set; }
        public bool IsNetworkError { get; set; }
        public string Body { get; set; }
        public string ErrorText { get; set; }
        public Dictionary<string, string> Headers { get; } = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        public double DurationMs { get; set; }

        public bool IsSuccess => !IsNetworkError && StatusCode >= 200 && StatusCode < 300;
    }

    [Serializable]
    public sealed class ApiTraceEntry
    {
        public string timestampUtc;
        public string requestId;
        public string method;
        public string url;
        public int statusCode;
        public double durationMs;
        public bool succeeded;
        public bool wasRetried;
        public string requestBodyPreview;
        public string responseBodyPreview;
    }

    [Serializable]
    public sealed class TokenValidationResult
    {
        public bool isValid;
        public string accountId;
        public string displayName;
        public bool isGuest;
        public List<string> roles = new List<string>();
        public long expiresAtUnixSeconds;
        public string failureCode;
        public string failureReason;
    }

    [Serializable]
    public sealed class AuthProfileUpdateRequest
    {
        public string displayName;
        public string avatarUrl;
        public string metadataJson;
    }
}
