using System;
using System.Threading;
using System.Threading.Tasks;
using UnityAuthCore.Core;

namespace UnityAuthCore.Http
{
    public sealed class RequestIdInterceptor : IApiInterceptor
    {
        public Task OnBeforeSendAsync(ApiRequest request, CancellationToken ct = default)
        {
            if (request != null && !request.Headers.ContainsKey("X-Request-Id"))
            {
                request.Headers["X-Request-Id"] = Guid.NewGuid().ToString("N");
            }
            return Task.CompletedTask;
        }

        public Task OnAfterReceiveAsync(ApiRequest request, HttpRawResponse response, CancellationToken ct = default)
        {
            return Task.CompletedTask;
        }
    }

    public sealed class BearerAuthInterceptor : IApiInterceptor
    {
        private readonly Func<string> _accessTokenProvider;

        public BearerAuthInterceptor(Func<string> accessTokenProvider)
        {
            _accessTokenProvider = accessTokenProvider;
        }

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

        public Task OnAfterReceiveAsync(ApiRequest request, HttpRawResponse response, CancellationToken ct = default)
        {
            return Task.CompletedTask;
        }
    }

    public sealed class ExponentialBackoffRetryPolicy : IRetryPolicy
    {
        private readonly int _maxRetries;
        private readonly int _baseDelayMs;
        private readonly int _maxDelayMs;
        private readonly Random _jitter = new Random();

        public ExponentialBackoffRetryPolicy(int maxRetries = 2, int baseDelayMs = 200, int maxDelayMs = 4000)
        {
            _maxRetries = Math.Max(0, maxRetries);
            _baseDelayMs = Math.Max(10, baseDelayMs);
            _maxDelayMs = Math.Max(_baseDelayMs, maxDelayMs);
        }

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

            int expDelay = _baseDelayMs * (1 << Math.Min(attempt, 6));
            int jitter = _jitter.Next(0, Math.Max(1, expDelay / 4));
            delayMs = Math.Min(_maxDelayMs, expDelay + jitter);
            return true;
        }
    }
}
