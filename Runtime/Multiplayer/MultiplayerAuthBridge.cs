using System;
using System.Collections.Generic;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using UnityAuthCore.Core;
using UnityAuthCore.Security;
using UnityEngine;

namespace UnityAuthCore.Multiplayer
{
    /// <summary>
    /// Wire-ready connection payload sent by game clients during NGO ConnectionApproval,
    /// Mirror NetworkAuthenticator, or FishNet Authenticator handshakes.
    /// </summary>
    [Serializable]
    public sealed class MultiplayerAuthTicket
    {
        public string accessToken;
        public string clientVersion;
        public string nonce;
        public long issuedAtUnixSeconds;

        public byte[] ToUtf8Bytes()
        {
            return Encoding.UTF8.GetBytes(JsonUtility.ToJson(this));
        }

        public static bool TryFromUtf8Bytes(byte[] payload, out MultiplayerAuthTicket ticket, out string error)
        {
            ticket = null;
            error = null;
            if (payload == null || payload.Length == 0)
            {
                error = "Connection payload is empty.";
                return false;
            }

            try
            {
                string json = Encoding.UTF8.GetString(payload);
                ticket = JsonUtility.FromJson<MultiplayerAuthTicket>(json);
                if (ticket == null || string.IsNullOrWhiteSpace(ticket.accessToken))
                {
                    error = "Connection payload does not contain an accessToken.";
                    return false;
                }
                return true;
            }
            catch (Exception ex)
            {
                error = $"Failed to parse MultiplayerAuthTicket: {ex.Message}";
                return false;
            }
        }
    }

    [Serializable]
    public sealed class MultiplayerVerifiedIdentity
    {
        public ulong clientId;
        public string accountId;
        public string displayName;
        public bool isGuest;
        public List<string> roles = new List<string>();
        public long expiresAtUnixSeconds;
        public long authenticatedAtUnixSeconds;
    }

    public sealed class MultiplayerApprovalResult
    {
        public bool Approved { get; set; }
        public MultiplayerVerifiedIdentity Identity { get; set; }
        public string RejectionCode { get; set; }
        public string RejectionReason { get; set; }
        public ulong? DisplacedPreviousClientId { get; set; }
    }

    /// <summary>
    /// Fast offline HS256 JWT validator for Dedicated Servers / Hosts sharing the auth signing secret.
    /// </summary>
    public sealed class LocalHs256JwtValidator : IServerTokenValidator
    {
        private readonly string _secret;
        private readonly string _expectedIssuer;
        private readonly string _expectedAudience;
        private readonly int _clockSkewSeconds;
        private readonly Func<DateTime> _utcNow;

        public LocalHs256JwtValidator(
            string secret,
            string expectedIssuer = null,
            string expectedAudience = null,
            int clockSkewSeconds = 30,
            Func<DateTime> utcNowProvider = null)
        {
            _secret = secret;
            _expectedIssuer = expectedIssuer;
            _expectedAudience = expectedAudience;
            _clockSkewSeconds = clockSkewSeconds;
            _utcNow = utcNowProvider ?? (() => DateTime.UtcNow);
        }

        public Task<TokenValidationResult> ValidateAsync(string accessToken, CancellationToken ct = default)
        {
            var res = JwtUtility.VerifyHs256(accessToken, _secret, _expectedIssuer, _expectedAudience, _clockSkewSeconds, _utcNow());
            return Task.FromResult(res);
        }
    }

    /// <summary>
    /// Remote token validator delegating verification to IAuthBackendAdapter.IntrospectTokenAsync
    /// (works with self-hosted /v1/auth/introspect or BaaS user-verification adapters).
    /// </summary>
    public sealed class RemoteIntrospectionValidator : IServerTokenValidator
    {
        private readonly IAuthBackendAdapter _adapter;
        private readonly string _serverApiKey;

        public RemoteIntrospectionValidator(IAuthBackendAdapter adapter, string serverApiKey = null)
        {
            _adapter = adapter ?? throw new ArgumentNullException(nameof(adapter));
            _serverApiKey = serverApiKey;
        }

        public async Task<TokenValidationResult> ValidateAsync(string accessToken, CancellationToken ct = default)
        {
            var res = await _adapter.IntrospectTokenAsync(accessToken, _serverApiKey, ct);
            if (!res.Succeeded || res.Data == null)
            {
                return new TokenValidationResult
                {
                    isValid = false,
                    failureCode = res.Error != null ? res.Error.errorCode : "INTROSPECTION_FAILED",
                    failureReason = res.Error != null ? res.Error.message : "Remote token introspection failed."
                };
            }
            return res.Data;
        }
    }

    /// <summary>
    /// Transport-agnostic Unity Multiplayer authentication bridge.
    /// Builds client connection payloads and verifies them on the server while tracking active clientId -> accountId mappings.
    /// </summary>
    public sealed class MultiplayerAuthBridge
    {
        private readonly Dictionary<ulong, MultiplayerVerifiedIdentity> _byClientId = new Dictionary<ulong, MultiplayerVerifiedIdentity>();
        private readonly Dictionary<string, ulong> _clientIdByAccount = new Dictionary<string, ulong>(StringComparer.Ordinal);

        public bool RejectDuplicateAccountLogin { get; set; } = false;
        public string RequiredClientVersion { get; set; } = string.Empty;
        public int ActivePlayerCount => _byClientId.Count;

        public static byte[] BuildClientConnectionPayload(AuthSession session, string clientVersion = "1.0.0")
        {
            if (session == null || !session.HasAccessToken)
            {
                return Array.Empty<byte>();
            }

            var ticket = new MultiplayerAuthTicket
            {
                accessToken = session.accessToken,
                clientVersion = clientVersion ?? string.Empty,
                nonce = Guid.NewGuid().ToString("N"),
                issuedAtUnixSeconds = DateTimeOffset.UtcNow.ToUnixTimeSeconds()
            };
            return ticket.ToUtf8Bytes();
        }

        public async Task<MultiplayerApprovalResult> ApproveConnectionAsync(
            ulong clientId,
            byte[] connectionPayload,
            IServerTokenValidator validator,
            CancellationToken ct = default)
        {
            if (validator == null)
            {
                return Reject("VALIDATOR_MISSING", "No IServerTokenValidator configured on the server.");
            }

            if (!MultiplayerAuthTicket.TryFromUtf8Bytes(connectionPayload, out MultiplayerAuthTicket ticket, out string parseError))
            {
                return Reject("INVALID_PAYLOAD", parseError);
            }

            if (!string.IsNullOrEmpty(RequiredClientVersion) &&
                !string.Equals(ticket.clientVersion, RequiredClientVersion, StringComparison.Ordinal))
            {
                return Reject("VERSION_MISMATCH", $"Expected client version {RequiredClientVersion}, got {ticket.clientVersion}.");
            }

            TokenValidationResult validation = await validator.ValidateAsync(ticket.accessToken, ct);
            if (validation == null || !validation.isValid)
            {
                return Reject(
                    validation?.failureCode ?? "TOKEN_INVALID",
                    validation?.failureReason ?? "Access token validation failed.");
            }

            ulong? displaced = null;
            if (_clientIdByAccount.TryGetValue(validation.accountId, out ulong existingClientId) && existingClientId != clientId)
            {
                if (RejectDuplicateAccountLogin)
                {
                    return Reject("ACCOUNT_ALREADY_CONNECTED", $"Account {validation.accountId} is already connected on client {existingClientId}.");
                }

                displaced = existingClientId;
                _byClientId.Remove(existingClientId);
            }

            var identity = new MultiplayerVerifiedIdentity
            {
                clientId = clientId,
                accountId = validation.accountId,
                displayName = validation.displayName,
                isGuest = validation.isGuest,
                roles = validation.roles != null ? new List<string>(validation.roles) : new List<string>(),
                expiresAtUnixSeconds = validation.expiresAtUnixSeconds,
                authenticatedAtUnixSeconds = DateTimeOffset.UtcNow.ToUnixTimeSeconds()
            };

            _byClientId[clientId] = identity;
            _clientIdByAccount[identity.accountId] = clientId;

            return new MultiplayerApprovalResult
            {
                Approved = true,
                Identity = identity,
                DisplacedPreviousClientId = displaced
            };
        }

        public bool TryGetIdentity(ulong clientId, out MultiplayerVerifiedIdentity identity) =>
            _byClientId.TryGetValue(clientId, out identity);

        public void HandleClientDisconnected(ulong clientId)
        {
            if (_byClientId.TryGetValue(clientId, out MultiplayerVerifiedIdentity identity))
            {
                _byClientId.Remove(clientId);
                if (_clientIdByAccount.TryGetValue(identity.accountId, out ulong mapped) && mapped == clientId)
                {
                    _clientIdByAccount.Remove(identity.accountId);
                }
            }
        }

        public void Clear()
        {
            _byClientId.Clear();
            _clientIdByAccount.Clear();
        }

        private static MultiplayerApprovalResult Reject(string code, string reason)
        {
            return new MultiplayerApprovalResult
            {
                Approved = false,
                RejectionCode = code,
                RejectionReason = reason
            };
        }
    }
}
