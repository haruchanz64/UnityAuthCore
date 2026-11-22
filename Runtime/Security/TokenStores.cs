using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using UnityAuthCore.Core;
using UnityEngine;

namespace UnityAuthCore.Security
{
    /// <summary>
    /// Volatile <see cref="ITokenStore"/> that clones and holds the active <see cref="AuthSession"/> in memory only.
    /// Useful for Editor consoles, headless dedicated servers, and unit tests.
    /// </summary>
    public sealed class InMemoryTokenStore : ITokenStore
    {
        private AuthSession _session;

        /// <inheritdoc/>
        public Task SaveAsync(AuthSession session, CancellationToken ct = default)
        {
            _session = session != null ? session.Clone() : null;
            return Task.CompletedTask;
        }

        /// <inheritdoc/>
        public Task<AuthSession> LoadAsync(CancellationToken ct = default)
        {
            return Task.FromResult(_session != null ? _session.Clone() : null);
        }

        /// <inheritdoc/>
        public Task ClearAsync(CancellationToken ct = default)
        {
            _session = null;
            return Task.CompletedTask;
        }
    }

    /// <summary>
    /// Persistent <see cref="ITokenStore"/> using AES-256-CBC with Encrypt-then-MAC (HMAC-SHA256).
    /// Rejects modified or truncated files cleanly instead of loading corrupted sessions.
    /// </summary>
    public sealed class EncryptedFileTokenStore : ITokenStore
    {
        private readonly string _filePath;
        private readonly byte[] _encKey;
        private readonly byte[] _macKey;

        /// <summary>Absolute file path where the encrypted session envelope is written.</summary>
        public string FilePath => _filePath;

        /// <summary>
        /// Creates an encrypted file store deriving separate encryption and MAC keys via domain-separated SHA-256 hashes.
        /// </summary>
        /// <param name="filePath">Target file path; defaults to <c>unity_auth_core_session.dat</c> under <see cref="Application.persistentDataPath"/>.</param>
        /// <param name="passphrase">Optional key derivation secret; defaults to a device-scoped value combining <see cref="Application.identifier"/> and <see cref="SystemInfo.deviceUniqueIdentifier"/>.</param>
        public EncryptedFileTokenStore(string filePath = null, string passphrase = null)
        {
            _filePath = string.IsNullOrWhiteSpace(filePath)
                ? Path.Combine(Application.persistentDataPath, "unity_auth_core_session.dat")
                : filePath;

            string effectiveSecret = string.IsNullOrEmpty(passphrase)
                ? $"{Application.identifier}:{SystemInfo.deviceUniqueIdentifier}:UnityAuthCore.v1"
                : passphrase;

            using (var sha = SHA256.Create())
            {
                _encKey = sha.ComputeHash(Encoding.UTF8.GetBytes("enc:" + effectiveSecret));
                _macKey = sha.ComputeHash(Encoding.UTF8.GetBytes("mac:" + effectiveSecret));
            }
        }

        /// <summary>
        /// Encrypts and authenticates <paramref name="session"/> to disk as <c>[32-byte HMAC][16-byte IV][AES-256-CBC ciphertext]</c>.
        /// Deletes the file if <paramref name="session"/> is null.
        /// </summary>
        /// <param name="session">Session to persist, or null to clear stored data.</param>
        /// <param name="ct">Optional cancellation token.</param>
        public Task SaveAsync(AuthSession session, CancellationToken ct = default)
        {
            if (session == null)
            {
                return ClearAsync(ct);
            }

            string dir = Path.GetDirectoryName(_filePath);
            if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
            {
                Directory.CreateDirectory(dir);
            }

            byte[] plainBytes = Encoding.UTF8.GetBytes(JsonUtility.ToJson(session));
            byte[] iv;
            byte[] cipherBytes;

            using (var aes = Aes.Create())
            {
                aes.KeySize = 256;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;
                aes.Key = _encKey;
                aes.GenerateIV();
                iv = aes.IV;

                using (var enc = aes.CreateEncryptor())
                {
                    cipherBytes = enc.TransformFinalBlock(plainBytes, 0, plainBytes.Length);
                }
            }

            byte[] payload = new byte[iv.Length + cipherBytes.Length];
            Buffer.BlockCopy(iv, 0, payload, 0, iv.Length);
            Buffer.BlockCopy(cipherBytes, 0, payload, iv.Length, cipherBytes.Length);

            // Compute HMAC over IV + ciphertext (Encrypt-then-MAC)
            byte[] mac;
            using (var hmac = new HMACSHA256(_macKey))
            {
                mac = hmac.ComputeHash(payload);
            }

            byte[] envelope = new byte[mac.Length + payload.Length];
            Buffer.BlockCopy(mac, 0, envelope, 0, mac.Length);
            Buffer.BlockCopy(payload, 0, envelope, mac.Length, payload.Length);

            File.WriteAllBytes(_filePath, envelope);
            return Task.CompletedTask;
        }

        /// <summary>
        /// Verifies the stored HMAC-SHA256 tag in constant time before decrypting and deserializing the session.
        /// Returns null when the file is missing, truncated, tampered, or unreadable.
        /// </summary>
        /// <param name="ct">Optional cancellation token.</param>
        /// <returns>The decrypted <see cref="AuthSession"/>, or null if unavailable or invalid.</returns>
        public Task<AuthSession> LoadAsync(CancellationToken ct = default)
        {
            if (!File.Exists(_filePath))
            {
                return Task.FromResult<AuthSession>(null);
            }

            try
            {
                byte[] envelope = File.ReadAllBytes(_filePath);
                // Minimum valid envelope requires 32-byte HMAC + 16-byte IV + at least 1 byte of ciphertext
                if (envelope.Length <= 32 + 16)
                {
                    return Task.FromResult<AuthSession>(null);
                }

                byte[] storedMac = new byte[32];
                byte[] payload = new byte[envelope.Length - 32];
                Buffer.BlockCopy(envelope, 0, storedMac, 0, 32);
                Buffer.BlockCopy(envelope, 32, payload, 0, payload.Length);

                byte[] expectedMac;
                using (var hmac = new HMACSHA256(_macKey))
                {
                    expectedMac = hmac.ComputeHash(payload);
                }

                // Constant-time MAC verification before attempting AES decryption
                int diff = 0;
                for (int i = 0; i < 32; i++) diff |= storedMac[i] ^ expectedMac[i];
                if (diff != 0)
                {
                    return Task.FromResult<AuthSession>(null);
                }

                byte[] iv = new byte[16];
                byte[] cipher = new byte[payload.Length - 16];
                Buffer.BlockCopy(payload, 0, iv, 0, 16);
                Buffer.BlockCopy(payload, 16, cipher, 0, cipher.Length);

                using (var aes = Aes.Create())
                {
                    aes.KeySize = 256;
                    aes.Mode = CipherMode.CBC;
                    aes.Padding = PaddingMode.PKCS7;
                    aes.Key = _encKey;
                    aes.IV = iv;

                    using (var dec = aes.CreateDecryptor())
                    {
                        byte[] plain = dec.TransformFinalBlock(cipher, 0, cipher.Length);
                        string json = Encoding.UTF8.GetString(plain);
                        return Task.FromResult(JsonUtility.FromJson<AuthSession>(json));
                    }
                }
            }
            catch
            {
                return Task.FromResult<AuthSession>(null);
            }
        }

        /// <inheritdoc/>
        public Task ClearAsync(CancellationToken ct = default)
        {
            if (File.Exists(_filePath))
            {
                File.Delete(_filePath);
            }
            return Task.CompletedTask;
        }
    }
}
