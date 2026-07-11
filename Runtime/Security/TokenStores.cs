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
    public sealed class InMemoryTokenStore : ITokenStore
    {
        private AuthSession _session;

        public Task SaveAsync(AuthSession session, CancellationToken ct = default)
        {
            _session = session != null ? session.Clone() : null;
            return Task.CompletedTask;
        }

        public Task<AuthSession> LoadAsync(CancellationToken ct = default)
        {
            return Task.FromResult(_session != null ? _session.Clone() : null);
        }

        public Task ClearAsync(CancellationToken ct = default)
        {
            _session = null;
            return Task.CompletedTask;
        }
    }

    /// <summary>
    /// Persistent ITokenStore using AES-256-CBC with Encrypt-then-MAC (HMAC-SHA256).
    /// Rejects modified or truncated files cleanly instead of loading corrupted sessions.
    /// </summary>
    public sealed class EncryptedFileTokenStore : ITokenStore
    {
        private readonly string _filePath;
        private readonly byte[] _encKey;
        private readonly byte[] _macKey;

        public string FilePath => _filePath;

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

        public Task<AuthSession> LoadAsync(CancellationToken ct = default)
        {
            if (!File.Exists(_filePath))
            {
                return Task.FromResult<AuthSession>(null);
            }

            try
            {
                byte[] envelope = File.ReadAllBytes(_filePath);
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
