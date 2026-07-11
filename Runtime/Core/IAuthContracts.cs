using System.Threading;
using System.Threading.Tasks;

namespace UnityAuthCore.Core
{
    /// <summary>
    /// Low-level HTTP transport contract (UnityWebRequest by default, or MockAuthTransport in tests).
    /// </summary>
    public interface IHttpTransport
    {
        Task<HttpRawResponse> SendAsync(ApiRequest request, CancellationToken ct = default);
    }

    /// <summary>
    /// Request/response middleware hook for Bearer headers, correlation IDs, telemetry, or signing.
    /// </summary>
    public interface IApiInterceptor
    {
        Task OnBeforeSendAsync(ApiRequest request, CancellationToken ct = default);
        Task OnAfterReceiveAsync(ApiRequest request, HttpRawResponse response, CancellationToken ct = default);
    }

    /// <summary>
    /// Retry decision policy for transient HTTP or network failures (429, 5xx, timeouts).
    /// </summary>
    public interface IRetryPolicy
    {
        bool ShouldRetry(ApiRequest request, HttpRawResponse response, int attempt, out int delayMs);
    }

    /// <summary>
    /// Pluggable session token persistence (in-memory, encrypted disk, keychain, or SaveEncryptionToolkit).
    /// </summary>
    public interface ITokenStore
    {
        Task SaveAsync(AuthSession session, CancellationToken ct = default);
        Task<AuthSession> LoadAsync(CancellationToken ct = default);
        Task ClearAsync(CancellationToken ct = default);
    }

    /// <summary>
    /// Backend-agnostic authentication adapter contract.
    /// Implement this interface to plug in any self-hosted server or BaaS (Supabase, Firebase, PlayFab, Steam, custom).
    /// </summary>
    public interface IAuthBackendAdapter
    {
        string ProviderId { get; }

        Task<AuthResult<AuthSession>> SignInGuestAsync(string deviceId, string displayName = null, CancellationToken ct = default);
        Task<AuthResult<AuthSession>> RegisterAsync(string email, string password, string displayName = null, CancellationToken ct = default);
        Task<AuthResult<AuthSession>> LoginAsync(string email, string password, CancellationToken ct = default);
        Task<AuthResult<AuthSession>> RefreshAsync(string refreshToken, CancellationToken ct = default);
        Task<AuthResult<bool>> LogoutAsync(string accessToken, string refreshToken, CancellationToken ct = default);
        Task<AuthResult<AuthUserProfile>> GetProfileAsync(CancellationToken ct = default);
        Task<AuthResult<AuthUserProfile>> UpdateProfileAsync(AuthProfileUpdateRequest update, CancellationToken ct = default);
        Task<AuthResult<AuthSession>> LinkEmailPasswordAsync(string email, string password, CancellationToken ct = default);
        Task<AuthResult<TokenValidationResult>> IntrospectTokenAsync(string accessToken, string serverApiKey = null, CancellationToken ct = default);
    }

    /// <summary>
    /// Dedicated game server / host token validator for Unity Multiplayer connection approval.
    /// </summary>
    public interface IServerTokenValidator
    {
        Task<TokenValidationResult> ValidateAsync(string accessToken, CancellationToken ct = default);
    }
}
