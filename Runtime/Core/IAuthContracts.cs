using System.Threading;
using System.Threading.Tasks;

namespace UnityAuthCore.Core
{
    /// <summary>
    /// Low-level HTTP transport contract (UnityWebRequest by default, or MockAuthTransport in tests).
    /// </summary>
    public interface IHttpTransport
    {
        /// <summary>
        /// Dispatches an HTTP request and returns the raw status, headers, body, and timing information.
        /// </summary>
        /// <param name="request">Request descriptor containing method, URL, headers, body, and timeout.</param>
        /// <param name="ct">Cancellation token used to abort the in-flight request.</param>
        /// <returns>The raw transport response.</returns>
        Task<HttpRawResponse> SendAsync(ApiRequest request, CancellationToken ct = default);
    }

    /// <summary>
    /// Request/response middleware hook for Bearer headers, correlation IDs, telemetry, or signing.
    /// </summary>
    public interface IApiInterceptor
    {
        /// <summary>
        /// Invoked in registration order before each transport send attempt.
        /// </summary>
        /// <param name="request">Outgoing request that may be inspected or mutated.</param>
        /// <param name="ct">Cancellation token for asynchronous middleware work.</param>
        Task OnBeforeSendAsync(ApiRequest request, CancellationToken ct = default);

        /// <summary>
        /// Invoked in reverse registration order after a raw response is received from the transport.
        /// </summary>
        /// <param name="request">The request that produced <paramref name="response"/>.</param>
        /// <param name="response">Raw response returned by the transport.</param>
        /// <param name="ct">Cancellation token for asynchronous middleware work.</param>
        Task OnAfterReceiveAsync(ApiRequest request, HttpRawResponse response, CancellationToken ct = default);
    }

    /// <summary>
    /// Retry decision policy for transient HTTP or network failures (429, 5xx, timeouts).
    /// </summary>
    public interface IRetryPolicy
    {
        /// <summary>
        /// Determines whether a failed request should be retried and how long to wait before the next attempt.
        /// </summary>
        /// <param name="request">The outgoing request.</param>
        /// <param name="response">The response from the failed attempt.</param>
        /// <param name="attempt">Zero-based retry counter for the current request.</param>
        /// <param name="delayMs">Outputs the delay in milliseconds before retrying when this method returns true.</param>
        /// <returns>True to retry after <paramref name="delayMs"/>; false to stop retrying.</returns>
        bool ShouldRetry(ApiRequest request, HttpRawResponse response, int attempt, out int delayMs);
    }

    /// <summary>
    /// Pluggable session token persistence (in-memory, encrypted disk, keychain, or SaveEncryptionToolkit).
    /// </summary>
    public interface ITokenStore
    {
        /// <summary>
        /// Persists the active session, or clears stored state when <paramref name="session"/> is null.
        /// </summary>
        /// <param name="session">Session to store.</param>
        /// <param name="ct">Optional cancellation token.</param>
        Task SaveAsync(AuthSession session, CancellationToken ct = default);

        /// <summary>
        /// Loads the previously persisted session, returning null if none exists or integrity checks fail.
        /// </summary>
        /// <param name="ct">Optional cancellation token.</param>
        /// <returns>The restored <see cref="AuthSession"/>, or null when unavailable.</returns>
        Task<AuthSession> LoadAsync(CancellationToken ct = default);

        /// <summary>
        /// Deletes any persisted session data from storage.
        /// </summary>
        /// <param name="ct">Optional cancellation token.</param>
        Task ClearAsync(CancellationToken ct = default);
    }

    /// <summary>
    /// Backend-agnostic authentication adapter contract.
    /// Implement this interface to plug in any self-hosted server or BaaS (Supabase, Firebase, PlayFab, Steam, custom).
    /// </summary>
    public interface IAuthBackendAdapter
    {
        /// <summary>Short identifier naming this backend provider (for example, <c>rest</c>, <c>supabase</c>, or <c>firebase</c>).</summary>
        string ProviderId { get; }

        /// <summary>
        /// Creates or signs into an anonymous guest account bound to <paramref name="deviceId"/>.
        /// </summary>
        /// <param name="deviceId">Device identifier used to recognize returning guests; may fall back to a generated ID.</param>
        /// <param name="displayName">Optional initial display name for new guest accounts.</param>
        /// <param name="ct">Optional cancellation token.</param>
        /// <returns>An <see cref="AuthResult{T}"/> containing the issued <see cref="AuthSession"/> on success.</returns>
        Task<AuthResult<AuthSession>> SignInGuestAsync(string deviceId, string displayName = null, CancellationToken ct = default);

        /// <summary>
        /// Registers a new account using email and password credentials.
        /// </summary>
        /// <param name="email">Player email address.</param>
        /// <param name="password">Plaintext password sent over the configured transport.</param>
        /// <param name="displayName">Optional display name for the new account.</param>
        /// <param name="ct">Optional cancellation token.</param>
        /// <returns>An <see cref="AuthResult{T}"/> containing the newly created <see cref="AuthSession"/>.</returns>
        Task<AuthResult<AuthSession>> RegisterAsync(string email, string password, string displayName = null, CancellationToken ct = default);

        /// <summary>
        /// Authenticates an existing account with email and password credentials.
        /// </summary>
        /// <param name="email">Registered email address.</param>
        /// <param name="password">Account password.</param>
        /// <param name="ct">Optional cancellation token.</param>
        /// <returns>An <see cref="AuthResult{T}"/> containing the authenticated <see cref="AuthSession"/>.</returns>
        Task<AuthResult<AuthSession>> LoginAsync(string email, string password, CancellationToken ct = default);

        /// <summary>
        /// Exchanges a refresh token for a fresh access token and rotated refresh token.
        /// </summary>
        /// <param name="refreshToken">Current refresh token from the active session.</param>
        /// <param name="ct">Optional cancellation token.</param>
        /// <returns>An <see cref="AuthResult{T}"/> containing the rotated <see cref="AuthSession"/>.</returns>
        Task<AuthResult<AuthSession>> RefreshAsync(string refreshToken, CancellationToken ct = default);

        /// <summary>
        /// Revokes the active session on the backend.
        /// </summary>
        /// <param name="accessToken">Current bearer access token, if available.</param>
        /// <param name="refreshToken">Current refresh token to revoke, if available.</param>
        /// <param name="ct">Optional cancellation token.</param>
        /// <returns>An <see cref="AuthResult{T}"/> indicating whether server-side logout succeeded.</returns>
        Task<AuthResult<bool>> LogoutAsync(string accessToken, string refreshToken, CancellationToken ct = default);

        /// <summary>
        /// Fetches the profile for the currently authenticated account.
        /// </summary>
        /// <param name="ct">Optional cancellation token.</param>
        /// <returns>An <see cref="AuthResult{T}"/> containing the latest <see cref="AuthUserProfile"/>.</returns>
        Task<AuthResult<AuthUserProfile>> GetProfileAsync(CancellationToken ct = default);

        /// <summary>
        /// Applies partial profile updates for the currently authenticated account.
        /// </summary>
        /// <param name="update">Profile fields to update.</param>
        /// <param name="ct">Optional cancellation token.</param>
        /// <returns>An <see cref="AuthResult{T}"/> containing the updated <see cref="AuthUserProfile"/>.</returns>
        Task<AuthResult<AuthUserProfile>> UpdateProfileAsync(AuthProfileUpdateRequest update, CancellationToken ct = default);

        /// <summary>
        /// Upgrades the currently authenticated guest account by linking email and password credentials.
        /// </summary>
        /// <param name="email">Email address to bind to the account.</param>
        /// <param name="password">Password to bind to the account.</param>
        /// <param name="ct">Optional cancellation token.</param>
        /// <returns>An <see cref="AuthResult{T}"/> containing the refreshed non-guest <see cref="AuthSession"/>.</returns>
        Task<AuthResult<AuthSession>> LinkEmailPasswordAsync(string email, string password, CancellationToken ct = default);

        /// <summary>
        /// Validates an access token against the backend on behalf of a dedicated game server or host.
        /// </summary>
        /// <param name="accessToken">Client access token to inspect.</param>
        /// <param name="serverApiKey">Optional privileged server key sent via <c>X-Server-Key</c> or provider equivalent.</param>
        /// <param name="ct">Optional cancellation token.</param>
        /// <returns>An <see cref="AuthResult{T}"/> wrapping the <see cref="TokenValidationResult"/>.</returns>
        Task<AuthResult<TokenValidationResult>> IntrospectTokenAsync(string accessToken, string serverApiKey = null, CancellationToken ct = default);
    }

    /// <summary>
    /// Dedicated game server / host token validator for Unity Multiplayer connection approval.
    /// </summary>
    public interface IServerTokenValidator
    {
        /// <summary>
        /// Validates a client-supplied access token and returns the verified player identity or failure reason.
        /// </summary>
        /// <param name="accessToken">Access token extracted from a client's connection payload.</param>
        /// <param name="ct">Optional cancellation token.</param>
        /// <returns>Validation result with <see cref="TokenValidationResult.isValid"/> set accordingly.</returns>
        Task<TokenValidationResult> ValidateAsync(string accessToken, CancellationToken ct = default);
    }
}
