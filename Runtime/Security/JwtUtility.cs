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

        /// <summary>
        /// Encodes raw bytes using RFC 7515 unpadded Base64Url encoding.
        /// </summary>
        /// <param name="bytes">Input bytes to encode.</param>
        /// <returns>Base64Url string without trailing <c>=</c> padding.</returns>
        public static string Base64UrlEncode(byte[] bytes)
        {
            return Convert.ToBase64String(bytes)
                .TrimEnd('=')
                .Replace('+', '-')
                .Replace('/', '_');
        }

        /// <summary>
        /// Decodes an unpadded or padded Base64Url string back to raw bytes.
        /// </summary>
        /// <param name="input">Base64Url-encoded string; returns an empty array when null or empty.</param>
        /// <returns>Decoded byte array.</returns>
        public static byte[] Base64UrlDecode(string input)
        {
            if (string.IsNullOrEmpty(input)) return Array.Empty<byte>();
            string s = input.Replace('-', '+').Replace('_', '/');
            // Restore standard Base64 padding before decoding
            switch (s.Length % 4)
            {
                case 2: s += "=="; break;
                case 3: s += "="; break;
            }
            return Convert.FromBase64String(s);
        }

        /// <summary>
        /// Serializes <paramref name="claims"/> into a compact JWT signed with HMAC-SHA256 (<c>HS256</c>).
        /// Generates a random <c>jti</c> when <see cref="JwtClaims.jti"/> is empty.
        /// </summary>
        /// <param name="claims">Claims payload to encode.</param>
        /// <param name="secret">UTF-8 signing key shared with the verifying server.</param>
        /// <returns>Compact three-segment JWT string (<c>header.payload.signature</c>).</returns>
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

        /// <summary>
        /// Decodes the header and payload segments of a JWT without verifying its cryptographic signature.
        /// </summary>
        /// <param name="jwt">Compact JWT string to inspect.</param>
        /// <param name="claims">Outputs the decoded <see cref="JwtClaims"/> on success; otherwise null.</param>
        /// <param name="error">Outputs a parse failure reason when returning false; otherwise null.</param>
        /// <returns>True when the token has three segments and valid Base64Url JSON payload.</returns>
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

        /// <summary>
        /// Verifies a JWT's HS256 signature in constant time and validates expiry, issuer, and audience claims.
        /// </summary>
        /// <param name="jwt">Compact JWT string to verify.</param>
        /// <param name="secret">Expected HS256 signing secret.</param>
        /// <param name="expectedIssuer">Optional required <c>iss</c> claim; skipped when null or empty.</param>
        /// <param name="expectedAudience">Optional required <c>aud</c> claim; skipped when null or empty.</param>
        /// <param name="clockSkewSeconds">Allowed clock drift in seconds after <c>exp</c>; clamped to 0 minimum.</param>
        /// <param name="utcNow">Optional UTC clock override for tests; defaults to <see cref="DateTime.UtcNow"/>.</param>
        /// <returns>A <see cref="TokenValidationResult"/> with verified identity fields or a failure code and reason.</returns>
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

        /// <summary>
        /// Computes the raw HMAC-SHA256 digest of UTF-8 <paramref name="data"/> using <paramref name="secret"/>.
        /// </summary>
        private static byte[] ComputeHmacSha256(string data, string secret)
        {
            using (var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(secret)))
            {
                return hmac.ComputeHash(Encoding.UTF8.GetBytes(data));
            }
        }

        /// <summary>
        /// Compares two equal-length byte arrays without short-circuiting to mitigate timing side channels.
        /// </summary>
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

        /// <summary>
        /// Constructs a failed <see cref="TokenValidationResult"/> with the specified code and message.
        /// </summary>
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
