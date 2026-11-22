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
        /// <summary>Player bearer access token presented to the game server for validation.</summary>
        public string accessToken;
        /// <summary>Client application version string optionally matched against <see cref="MultiplayerAuthBridge.RequiredClientVersion"/>.</summary>
        public string clientVersion;
        /// <summary>Per-handshake random nonce generated when constructing the ticket.</summary>
        public string nonce;
        /// <summary>Client UTC timestamp in Unix epoch seconds when the ticket was assembled.</summary>
        public long issuedAtUnixSeconds;

        /// <summary>
        /// Serializes this ticket to UTF-8 JSON bytes suitable for transport connection payloads.
        /// </summary>
        /// <returns>UTF-8 encoded JSON byte array.</returns>
        public byte[] ToUtf8Bytes()
        {
            return Encoding.UTF8.GetBytes(JsonUtility.ToJson(this));
        }

        /// <summary>
        /// Parses a UTF-8 JSON connection payload into a <see cref="MultiplayerAuthTicket"/> and ensures <see cref="accessToken"/> is non-empty.
        /// </summary>
        /// <param name="payload">Raw payload bytes received during connection approval.</param>
        /// <param name="ticket">Outputs the parsed ticket on success; otherwise null.</param>
        /// <param name="error">Outputs a failure message when returning false; otherwise null.</param>
        /// <returns>True when the payload deserializes cleanly and contains a non-whitespace access token.</returns>
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

    /// <summary>
    /// Server-side record binding an approved network <see cref="clientId"/> to a verified player account.
    /// </summary>
    [Serializable]
    public sealed class MultiplayerVerifiedIdentity
    {
        /// <summary>Transport-assigned network client identifier.</summary>
        public ulong clientId;
        /// <summary>Verified backend account identifier.</summary>
        public string accountId;
        /// <summary>Verified player display name.</summary>
        public string displayName;
        /// <summary>True if the connected player is using a guest account.</summary>
        public bool isGuest;
        /// <summary>Authorization roles granted to the player.</summary>
        public List<string> roles = new List<string>();
        /// <summary>Access token expiration timestamp in Unix epoch seconds.</summary>
        public long expiresAtUnixSeconds;
        /// <summary>Server UTC timestamp in Unix epoch seconds when connection approval succeeded.</summary>
        public long authenticatedAtUnixSeconds;
    }

    /// <summary>
    /// Decision returned by <see cref="MultiplayerAuthBridge.ApproveConnectionAsync"/> for a connecting client.
    /// </summary>
    public sealed class MultiplayerApprovalResult
    {
        /// <summary>True when the connection handshake passed version, token, and duplicate-login checks.</summary>
        public bool Approved { get; set; }
        /// <summary>Verified identity registered for the client when <see cref="Approved"/> is true; otherwise null.</summary>
        public MultiplayerVerifiedIdentity Identity { get; set; }
        /// <summary>Machine-readable rejection code when <see cref="Approved"/> is false.</summary>
        public string RejectionCode { get; set; }
        /// <summary>Human-readable rejection reason suitable for disconnect messages when <see cref="Approved"/> is false.</summary>
        public string RejectionReason { get; set; }
        /// <summary>Previously connected client ID displaced by this login when duplicate logins replace older sessions; otherwise null.</summary>
        public ulong? DisplacedPreviousClientId { get; set; }
    }

    /// <summary>
    /// Fast offline HS256 JWT validator for Dedicated Servers or Hosts sharing the auth signing secret.
    /// </summary>
    public sealed class LocalHs256JwtValidator : IServerTokenValidator
    {
        private readonly string _secret;
        private readonly string _expectedIssuer;
        private readonly string _expectedAudience;
        private readonly int _clockSkewSeconds;
        private readonly Func<DateTime> _utcNow;

        /// <summary>
        /// Initializes a local HS256 validator checking signature, expiry, issuer, and audience claims.
        /// </summary>
        /// <param name="secret">Shared HS256 signing secret matching the auth server.</param>
        /// <param name="expectedIssuer">Optional required <c>iss</c> claim; ignored when null or empty.</param>
        /// <param name="expectedAudience">Optional required <c>aud</c> claim; ignored when null or empty.</param>
        /// <param name="clockSkewSeconds">Allowed clock drift in seconds after <c>exp</c>.</param>
        /// <param name="utcNowProvider">Optional UTC clock override for deterministic tests.</param>
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

        /// <inheritdoc/>
        public Task<TokenValidationResult> ValidateAsync(string accessToken, CancellationToken ct = default)
        {
            var res = JwtUtility.VerifyHs256(accessToken, _secret, _expectedIssuer, _expectedAudience, _clockSkewSeconds, _utcNow());
            return Task.FromResult(res);
        }
    }

    /// <summary>
    /// Remote token validator delegating verification to <see cref="IAuthBackendAdapter.IntrospectTokenAsync"/>
    /// (works with self-hosted <c>/v1/auth/introspect</c> or BaaS user-verification adapters).
    /// </summary>
    public sealed class RemoteIntrospectionValidator : IServerTokenValidator
    {
        private readonly IAuthBackendAdapter _adapter;
        private readonly string _serverApiKey;

        /// <summary>
        /// Initializes a remote introspection validator backed by <paramref name="adapter"/>.
        /// </summary>
        /// <param name="adapter">Backend adapter implementing <see cref="IAuthBackendAdapter.IntrospectTokenAsync"/>.</param>
        /// <param name="serverApiKey">Optional privileged server key forwarded as <c>X-Server-Key</c>.</param>
        public RemoteIntrospectionValidator(IAuthBackendAdapter adapter, string serverApiKey = null)
        {
            _adapter = adapter ?? throw new ArgumentNullException(nameof(adapter));
            _serverApiKey = serverApiKey;
        }

        /// <inheritdoc/>
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
    /// Builds client connection payloads and verifies them on the server while tracking active clientId to accountId mappings.
    /// </summary>
    public sealed class MultiplayerAuthBridge
    {
        private readonly Dictionary<ulong, MultiplayerVerifiedIdentity> _byClientId = new Dictionary<ulong, MultiplayerVerifiedIdentity>();
        private readonly Dictionary<string, ulong> _clientIdByAccount = new Dictionary<string, ulong>(StringComparer.Ordinal);

        /// <summary>
        /// When true, rejects a second connection using an already-connected account with <c>ACCOUNT_ALREADY_CONNECTED</c>.
        /// When false, approves the new client and reports the older client ID in <see cref="MultiplayerApprovalResult.DisplacedPreviousClientId"/>.
        /// </summary>
        public bool RejectDuplicateAccountLogin { get; set; } = false;
        /// <summary>Optional exact client version required on incoming tickets; empty disables version enforcement.</summary>
        public string RequiredClientVersion { get; set; } = string.Empty;
        /// <summary>Number of currently authenticated clients tracked in the server registry.</summary>
        public int ActivePlayerCount => _byClientId.Count;

        /// <summary>
        /// Encodes <paramref name="session"/> into a UTF-8 <see cref="MultiplayerAuthTicket"/> byte array for transport connection handshakes.
        /// </summary>
        /// <param name="session">Active client session; returns an empty array if null or missing an access token.</param>
        /// <param name="clientVersion">Client version string embedded in the ticket.</param>
        /// <returns>UTF-8 JSON payload bytes, or an empty array when no valid session is available.</returns>
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

        /// <summary>
        /// Parses and validates an incoming client's connection payload, enforces client version and duplicate-login policies,
        /// and registers the verified identity on success.
        /// </summary>
        /// <param name="clientId">Network transport client identifier requesting connection approval.</param>
        /// <param name="connectionPayload">UTF-8 encoded <see cref="MultiplayerAuthTicket"/> bytes sent by the client.</param>
        /// <param name="validator">Token validator performing local HS256 or remote introspection verification.</param>
        /// <param name="ct">Optional cancellation token.</param>
        /// <returns>An approval decision containing the verified identity, optional displaced client ID, or rejection details.</returns>
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

        /// <summary>
        /// Looks up the verified identity currently associated with <paramref name="clientId"/>.
        /// </summary>
        /// <param name="clientId">Network client identifier to query.</param>
        /// <param name="identity">Outputs the verified identity when found; otherwise null.</param>
        /// <returns>True if <paramref name="clientId"/> is currently authenticated.</returns>
        public bool TryGetIdentity(ulong clientId, out MultiplayerVerifiedIdentity identity) =>
            _byClientId.TryGetValue(clientId, out identity);

        /// <summary>
        /// Removes <paramref name="clientId"/> from the active session registry when the client disconnects.
        /// Leaves the account mapping intact if a newer displaced client already took over that account.
        /// </summary>
        /// <param name="clientId">Disconnected network client identifier.</param>
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

        /// <summary>
        /// Clears all active client-to-account mappings from the server registry.
        /// </summary>
        public void Clear()
        {
            _byClientId.Clear();
            _clientIdByAccount.Clear();
        }

        /// <summary>
        /// Creates a rejected <see cref="MultiplayerApprovalResult"/> with the specified code and reason.
        /// </summary>
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
