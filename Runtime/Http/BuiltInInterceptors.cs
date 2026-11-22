using System;
using System.Threading;
using System.Threading.Tasks;
using UnityAuthCore.Core;

namespace UnityAuthCore.Http
{
    /// <summary>
    /// Interceptor that injects a unique <c>X-Request-Id</c> correlation header onto outgoing requests when not already set.
    /// </summary>
    public sealed class RequestIdInterceptor : IApiInterceptor
    {
        /// <inheritdoc/>
        public Task OnBeforeSendAsync(ApiRequest request, CancellationToken ct = default)
        {
            if (request != null && !request.Headers.ContainsKey("X-Request-Id"))
            {
                request.Headers["X-Request-Id"] = Guid.NewGuid().ToString("N");
            }
            return Task.CompletedTask;
        }

        /// <inheritdoc/>
        public Task OnAfterReceiveAsync(ApiRequest request, HttpRawResponse response, CancellationToken ct = default)
        {
            return Task.CompletedTask;
        }
    }

    /// <summary>
    /// Interceptor that attaches an <c>Authorization: Bearer</c> header to requests marked with <see cref="ApiRequest.RequiresAuth"/>.
    /// Re-evaluates the token provider on every send attempt so post-refresh replays pick up rotated tokens automatically.
    /// </summary>
    public sealed class BearerAuthInterceptor : IApiInterceptor
    {
        private readonly Func<string> _accessTokenProvider;

        /// <summary>
        /// Initializes a <see cref="BearerAuthInterceptor"/> using <paramref name="accessTokenProvider"/>.
        /// </summary>
        /// <param name="accessTokenProvider">Callback returning the current access token, or null/empty when signed out.</param>
        public BearerAuthInterceptor(Func<string> accessTokenProvider)
        {
            _accessTokenProvider = accessTokenProvider;
        }

        /// <inheritdoc/>
        public Task OnBeforeSendAsync(ApiRequest request, CancellationToken ct = default)
        {
            if (request != null && request.RequiresAuth && _accessTokenProvider != null)
            {
                string token = _accessTokenProvider();
                if (!string.IsNullOrWhiteSpace(token))
                {
                    request.Headers["Authorization"] = $"Bearer {token}";
                }
            }
            return Task.CompletedTask;
        }

        /// <inheritdoc/>
        public Task OnAfterReceiveAsync(ApiRequest request, HttpRawResponse response, CancellationToken ct = default)
        {
            return Task.CompletedTask;
        }
    }

    /// <summary>
    /// Retry policy using bounded exponential backoff with random jitter for network errors, HTTP 408, HTTP 429, and 5xx responses.
    /// Honors numeric <c>Retry-After</c> headers in seconds when present, capped at the configured maximum delay.
    /// </summary>
    public sealed class ExponentialBackoffRetryPolicy : IRetryPolicy
    {
        private readonly int _maxRetries;
        private readonly int _baseDelayMs;
        private readonly int _maxDelayMs;
        private readonly Random _jitter = new Random();

        /// <summary>
        /// Initializes an <see cref="ExponentialBackoffRetryPolicy"/>.
        /// </summary>
        /// <param name="maxRetries">Maximum retry attempts after the initial send; clamped to 0 minimum.</param>
        /// <param name="baseDelayMs">Initial backoff delay in milliseconds; clamped to 10 ms minimum.</param>
        /// <param name="maxDelayMs">Upper bound for any computed or <c>Retry-After</c> delay in milliseconds.</param>
        public ExponentialBackoffRetryPolicy(int maxRetries = 2, int baseDelayMs = 200, int maxDelayMs = 4000)
        {
            _maxRetries = Math.Max(0, maxRetries);
            _baseDelayMs = Math.Max(10, baseDelayMs);
            _maxDelayMs = Math.Max(_baseDelayMs, maxDelayMs);
        }

        /// <inheritdoc/>
        public bool ShouldRetry(ApiRequest request, HttpRawResponse response, int attempt, out int delayMs)
        {
            delayMs = 0;
            if (request == null || request.SkipRetry || attempt >= _maxRetries)
            {
                return false;
            }

            if (response == null) return false;

            bool isTransient = response.IsNetworkError ||
                               response.StatusCode == 408 ||
                               response.StatusCode == 429 ||
                               (response.StatusCode >= 500 && response.StatusCode <= 599);

            if (!isTransient) return false;

            if (response.Headers.TryGetValue("Retry-After", out string retryAfterRaw) &&
                int.TryParse(retryAfterRaw, out int retrySeconds) &&
                retrySeconds > 0)
            {
                delayMs = Math.Min(_maxDelayMs, retrySeconds * 1000);
                return true;
            }

            // Cap bit shift at 2^6 to avoid integer overflow on high retry counts
            int expDelay = _baseDelayMs * (1 << Math.Min(attempt, 6));
            int jitter = _jitter.Next(0, Math.Max(1, expDelay / 4));
            delayMs = Math.Min(_maxDelayMs, expDelay + jitter);
            return true;
        }
    }
}
