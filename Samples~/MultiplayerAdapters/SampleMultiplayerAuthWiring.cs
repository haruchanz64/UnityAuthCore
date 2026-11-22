using System.Threading.Tasks;
using UnityAuthCore.Components;
using UnityAuthCore.Config;
using UnityAuthCore.Core;
using UnityAuthCore.Multiplayer;
using UnityEngine;

namespace UnityAuthCore.Samples.Multiplayer
{
    /// <summary>
    /// Example showing how to integrate <see cref="MultiplayerAuthBridge"/> with Netcode for GameObjects (NGO),
    /// Mirror, or FishNet without coupling <c>UnityAuthCore.Runtime</c> to any single networking package.
    /// </summary>
    /// <remarks>
    /// For NGO (<c>com.unity.netcode.gameobjects</c>), assign <see cref="CreateOutgoingConnectionPayload"/> to
    /// <c>NetworkManager.Singleton.NetworkConfig.ConnectionData</c> before calling <c>StartClient()</c>,
    /// and await <see cref="ValidateIncomingClientAsync"/> inside <c>ConnectionApprovalCallback</c> while
    /// <c>response.Pending</c> is true.
    /// </remarks>
    public sealed class SampleMultiplayerAuthWiring : MonoBehaviour
    {
        [SerializeField] private AccountController accountController;
        [SerializeField] private AuthFrameworkConfig serverConfig;

        private readonly MultiplayerAuthBridge _bridge = new MultiplayerAuthBridge();
        private IServerTokenValidator _serverValidator;

        private void Awake()
        {
            if (serverConfig != null)
            {
                _serverValidator = serverConfig.CreateServerTokenValidator(
                    accountController != null ? accountController.Client.Adapter : null);
            }
        }

        /// <summary>
        /// Builds the UTF-8 connection payload from the local <see cref="AccountController"/> session.
        /// </summary>
        /// <returns>Serialized ticket bytes, or an empty array when <see cref="accountController"/> is unassigned or signed out.</returns>
        public byte[] CreateOutgoingConnectionPayload()
        {
            return accountController != null
                ? accountController.BuildMultiplayerConnectionPayload()
                : System.Array.Empty<byte>();
        }

        /// <summary>
        /// Validates an incoming client handshake payload against the configured <see cref="IServerTokenValidator"/>
        /// and logs the approval or rejection result.
        /// </summary>
        /// <param name="clientId">Network client identifier assigned by the transport.</param>
        /// <param name="payload">Raw UTF-8 connection ticket bytes sent by the connecting client.</param>
        /// <returns>The <see cref="MultiplayerApprovalResult"/> decision.</returns>
        public async Task<MultiplayerApprovalResult> ValidateIncomingClientAsync(ulong clientId, byte[] payload)
        {
            var approval = await _bridge.ApproveConnectionAsync(clientId, payload, _serverValidator);
            if (approval.Approved)
            {
                Debug.Log($"[SampleMultiplayerAuthWiring] Approved client {clientId} as {approval.Identity.accountId} ({approval.Identity.displayName}).");
            }
            else
            {
                Debug.LogWarning($"[SampleMultiplayerAuthWiring] Rejected client {clientId}: {approval.RejectionCode} - {approval.RejectionReason}");
            }
            return approval;
        }

        /// <summary>
        /// Unregisters <paramref name="clientId"/> from the server's active authenticated player table.
        /// </summary>
        /// <param name="clientId">Disconnected network client identifier.</param>
        public void OnClientDisconnected(ulong clientId)
        {
            _bridge.HandleClientDisconnected(clientId);
        }
    }
}
