using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using UnityAuthCore.Core;
using UnityEngine;

namespace UnityAuthCore.Security
{
    /// <summary>
    /// Pure C# JWT utilities: Base64Url encoding, claims decoding, HS256 signing,
    /// and constant-time HS256 signature verification without external packages.
    /// </summary>
    public static class JwtUtility
    {
        [Serializable]
        private sealed class JwtPayloadDto
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
        }

        [Serializable]
        private sealed class JwtHeaderDto
        {
            public string alg = "HS256";
            public string typ = "JWT";
        }

        public static string Base64UrlEncode(byte[] bytes)
        {
            return Convert.ToBase64String(bytes)
                .TrimEnd('=')
                .Replace('+', '-')
                .Replace('/', '_');
        }

        public static byte[] Base64UrlDecode(string input)
        {
            if (string.IsNullOrEmpty(input)) return Array.Empty<byte>();
            string s = input.Replace('-', '+').Replace('_', '/');
            switch (s.Length % 4)
            {
                case 2: s += "=="; break;
                case 3: s += "="; break;
            }
            return Convert.FromBase64String(s);
        }

        public static string CreateHs256Token(JwtClaims claims, string secret)
        {
            if (claims == null) throw new ArgumentNullException(nameof(claims));
            if (string.IsNullOrEmpty(secret)) throw new ArgumentException("JWT secret cannot be empty.", nameof(secret));

            var header = new JwtHeaderDto { alg = "HS256", typ = "JWT" };
            var payload = new JwtPayloadDto
            {
                sub = claims.sub,
                iss = claims.iss,
                aud = claims.aud,
                email = claims.email,
                displayName = claims.displayName,
                isGuest = claims.isGuest,
                jti = string.IsNullOrEmpty(claims.jti) ? Guid.NewGuid().ToString("N") : claims.jti,
                iat = claims.iat,
                exp = claims.exp,
                roles = claims.roles != null ? new List<string>(claims.roles) : new List<string>()
            };

            string headerPart = Base64UrlEncode(Encoding.UTF8.GetBytes(JsonUtility.ToJson(header)));
            string payloadPart = Base64UrlEncode(Encoding.UTF8.GetBytes(JsonUtility.ToJson(payload)));
            string signingInput = $"{headerPart}.{payloadPart}";

            byte[] sigBytes = ComputeHmacSha256(signingInput, secret);
            return $"{signingInput}.{Base64UrlEncode(sigBytes)}";
        }

        public static bool TryParseClaims(string jwt, out JwtClaims claims, out string error)
        {
            claims = null;
            error = null;

            if (string.IsNullOrWhiteSpace(jwt))
            {
                error = "Token is empty.";
                return false;
            }

            string[] parts = jwt.Split('.');
            if (parts.Length != 3)
            {
                error = "Token must have three dot-separated segments.";
                return false;
            }

            try
            {
                string headerJson = Encoding.UTF8.GetString(Base64UrlDecode(parts[0]));
                string payloadJson = Encoding.UTF8.GetString(Base64UrlDecode(parts[1]));
                var dto = JsonUtility.FromJson<JwtPayloadDto>(payloadJson);
                if (dto == null)
                {
                    error = "Failed to deserialize JWT payload.";
                    return false;
                }

                claims = new JwtClaims
                {
                    sub = dto.sub,
                    iss = dto.iss,
                    aud = dto.aud,
                    email = dto.email,
                    displayName = dto.displayName,
                    isGuest = dto.isGuest,
                    jti = dto.jti,
                    iat = dto.iat,
                    exp = dto.exp,
                    roles = dto.roles ?? new List<string>(),
                    rawHeaderJson = headerJson,
                    rawPayloadJson = payloadJson
                };
                return true;
            }
            catch (Exception ex)
            {
                error = $"Invalid JWT encoding: {ex.Message}";
                return false;
            }
        }

        public static TokenValidationResult VerifyHs256(
            string jwt,
            string secret,
            string expectedIssuer = null,
            string expectedAudience = null,
            int clockSkewSeconds = 30,
            DateTime? utcNow = null)
        {
            if (string.IsNullOrWhiteSpace(jwt))
            {
                return Invalid("TOKEN_MISSING", "Access token is empty.");
            }

            if (string.IsNullOrWhiteSpace(secret))
            {
                return Invalid("SECRET_MISSING", "Server signing secret is not configured.");
            }

            string[] parts = jwt.Split('.');
            if (parts.Length != 3)
            {
                return Invalid("TOKEN_MALFORMED", "JWT does not contain three segments.");
            }

            if (!TryParseClaims(jwt, out JwtClaims claims, out string parseError))
            {
                return Invalid("TOKEN_PARSE_ERROR", parseError);
            }

            try
            {
                string signingInput = $"{parts[0]}.{parts[1]}";
                byte[] expectedSig = ComputeHmacSha256(signingInput, secret);
                byte[] providedSig = Base64UrlDecode(parts[2]);

                if (!FixedTimeEquals(expectedSig, providedSig))
                {
                    return Invalid("SIGNATURE_INVALID", "JWT HS256 signature verification failed.");
                }
            }
            catch (Exception ex)
            {
                return Invalid("SIGNATURE_ERROR", ex.Message);
            }

            long now = new DateTimeOffset(utcNow ?? DateTime.UtcNow).ToUnixTimeSeconds();
            if (claims.exp > 0 && now > claims.exp + Math.Max(0, clockSkewSeconds))
            {
                return Invalid("TOKEN_EXPIRED", "Access token has expired.");
            }

            if (!string.IsNullOrEmpty(expectedIssuer) && !string.Equals(claims.iss, expectedIssuer, StringComparison.Ordinal))
            {
                return Invalid("ISSUER_MISMATCH", $"Unexpected token issuer '{claims.iss}'.");
            }

            if (!string.IsNullOrEmpty(expectedAudience) && !string.Equals(claims.aud, expectedAudience, StringComparison.Ordinal))
            {
                return Invalid("AUDIENCE_MISMATCH", $"Unexpected token audience '{claims.aud}'.");
            }

            return new TokenValidationResult
            {
                isValid = true,
                accountId = claims.sub,
                displayName = claims.displayName,
                isGuest = claims.isGuest,
                roles = claims.roles != null ? new List<string>(claims.roles) : new List<string>(),
                expiresAtUnixSeconds = claims.exp
            };
        }

        private static byte[] ComputeHmacSha256(string data, string secret)
        {
            using (var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(secret)))
            {
                return hmac.ComputeHash(Encoding.UTF8.GetBytes(data));
            }
        }

        private static bool FixedTimeEquals(byte[] a, byte[] b)
        {
            if (a == null || b == null || a.Length != b.Length) return false;
            int diff = 0;
            for (int i = 0; i < a.Length; i++)
            {
                diff |= a[i] ^ b[i];
            }
            return diff == 0;
        }

        private static TokenValidationResult Invalid(string code, string reason)
        {
            return new TokenValidationResult
            {
                isValid = false,
                failureCode = code,
                failureReason = reason
            };
        }
    }
}
