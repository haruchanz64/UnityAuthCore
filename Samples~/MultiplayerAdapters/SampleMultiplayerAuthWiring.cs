using System.Threading.Tasks;
using UnityAuthCore.Components;
using UnityAuthCore.Config;
using UnityAuthCore.Core;
using UnityAuthCore.Multiplayer;
using UnityEngine;

namespace UnityAuthCore.Samples.Multiplayer
{
    /// <summary>
    /// Example showing how to integrate MultiplayerAuthBridge with Netcode for GameObjects (NGO),
    /// Mirror, or FishNet without coupling UnityAuthCore.Runtime to any single networking package.
    ///
    /// NGO wiring snippet (when com.unity.netcode.gameobjects is installed):
    ///   // Client before StartClient():
    ///   NetworkManager.Singleton.NetworkConfig.ConnectionData = accountController.BuildMultiplayerConnectionPayload();
    ///   NetworkManager.Singleton.StartClient();
    ///
    ///   // Server / Host ConnectionApprovalCallback:
    ///   NetworkManager.Singleton.ConnectionApprovalCallback = async (request, response) =>
    ///   {
    ///       response.Pending = true;
    ///       var approval = await bridge.ApproveConnectionAsync(request.ClientNetworkId, request.Payload, serverValidator);
    ///       response.Approved = approval.Approved;
    ///       response.CreatePlayerObject = approval.Approved;
    ///       response.Reason = approval.RejectionReason;
    ///       response.Pending = false;
    ///   };
    /// </summary>
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

        public byte[] CreateOutgoingConnectionPayload()
        {
            return accountController != null
                ? accountController.BuildMultiplayerConnectionPayload()
                : System.Array.Empty<byte>();
        }

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

        public void OnClientDisconnected(ulong clientId)
        {
            _bridge.HandleClientDisconnected(clientId);
        }
    }
}
