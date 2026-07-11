using System;
using System.Collections.Generic;
using System.Globalization;
using System.Threading;
using System.Threading.Tasks;
using UnityAuthCore.Core;
using UnityEngine;

namespace UnityAuthCore.Http
{
    /// <summary>
    /// Typed HTTP API client with interceptor pipeline, exponential backoff retries,
    /// live request tracing, and single-flight 401 token refresh coalescing.
    /// </summary>
    public sealed class ApiHttpClient
    {
        private readonly IHttpTransport _transport;
        private readonly IRetryPolicy _retryPolicy;
        private readonly List<IApiInterceptor> _interceptors = new List<IApiInterceptor>();
        private readonly List<ApiTraceEntry> _traces = new List<ApiTraceEntry>(128);
        private readonly int _maxTraces;
        private readonly object _refreshLock = new object();
        private Task<bool> _inFlightRefreshTask;

        public Func<CancellationToken, Task<bool>> OnUnauthorizedRefreshAsync { get; set; }
        public IReadOnlyList<ApiTraceEntry> Traces => _traces;
        public event Action<ApiTraceEntry> OnRequestTraced;

        public ApiHttpClient(
            IHttpTransport transport,
            IRetryPolicy retryPolicy = null,
            int maxTraces = 200)
        {
            _transport = transport ?? throw new ArgumentNullException(nameof(transport));
            _retryPolicy = retryPolicy ?? new ExponentialBackoffRetryPolicy();
            _maxTraces = Math.Max(10, maxTraces);
            _interceptors.Add(new RequestIdInterceptor());
        }

        public void AddInterceptor(IApiInterceptor interceptor)
        {
            if (interceptor != null && !_interceptors.Contains(interceptor))
            {
                _interceptors.Add(interceptor);
            }
        }

        public void ClearTraces() => _traces.Clear();

        public async Task<HttpRawResponse> SendRawAsync(ApiRequest request, CancellationToken ct = default)
        {
            if (request == null) throw new ArgumentNullException(nameof(request));

            bool attemptedRefresh = false;
            int attempt = 0;

            while (true)
            {
                for (int i = 0; i < _interceptors.Count; i++)
                {
                    await _interceptors[i].OnBeforeSendAsync(request, ct);
                }

                HttpRawResponse response = await _transport.SendAsync(request, ct);

                for (int i = _interceptors.Count - 1; i >= 0; i--)
                {
                    await _interceptors[i].OnAfterReceiveAsync(request, response, ct);
                }

                RecordTrace(request, response, attempt > 0 || attemptedRefresh);

                // Single-flight 401 refresh: concurrent unauthorized calls share one refresh request
                if (request.RequiresAuth &&
                    !attemptedRefresh &&
                    response.StatusCode == 401 &&
                    OnUnauthorizedRefreshAsync != null)
                {
                    attemptedRefresh = true;
                    bool refreshed = await ExecuteSingleFlightRefreshAsync(ct);
                    if (refreshed)
                    {
                        continue;
                    }
                    return response;
                }

                if (_retryPolicy != null && _retryPolicy.ShouldRetry(request, response, attempt, out int delayMs))
                {
                    attempt++;
                    if (delayMs > 0)
                    {
                        await Task.Delay(delayMs, ct);
                    }
                    continue;
                }

                return response;
            }
        }

        public async Task<AuthResult<T>> SendJsonAsync<T>(ApiRequest request, CancellationToken ct = default)
        {
            HttpRawResponse raw = await SendRawAsync(request, ct);
            if (!raw.IsSuccess)
            {
                return AuthResult<T>.Fail(ParseError(request, raw));
            }

            if (typeof(T) == typeof(bool))
            {
                return AuthResult<T>.Ok((T)(object)true, raw.StatusCode);
            }

            if (typeof(T) == typeof(string))
            {
                return AuthResult<T>.Ok((T)(object)(raw.Body ?? string.Empty), raw.StatusCode);
            }

            try
            {
                T parsed = string.IsNullOrWhiteSpace(raw.Body)
                    ? default
                    : JsonUtility.FromJson<T>(raw.Body);
                return AuthResult<T>.Ok(parsed, raw.StatusCode);
            }
            catch (Exception ex)
            {
                return AuthResult<T>.Fail(ApiError.Create(
                    raw.StatusCode,
                    "DESERIALIZATION_ERROR",
                    $"Failed to parse response as {typeof(T).Name}: {ex.Message}",
                    GetRequestId(request, raw)));
            }
        }

        private Task<bool> ExecuteSingleFlightRefreshAsync(CancellationToken ct)
        {
            Task<bool> sharedTask;
            lock (_refreshLock)
            {
                if (_inFlightRefreshTask == null || _inFlightRefreshTask.IsCompleted)
                {
                    _inFlightRefreshTask = RunRefreshCoreAsync(ct);
                }
                sharedTask = _inFlightRefreshTask;
            }
            return sharedTask;
        }

        private async Task<bool> RunRefreshCoreAsync(CancellationToken ct)
        {
            try
            {
                return await OnUnauthorizedRefreshAsync(ct);
            }
            catch
            {
                return false;
            }
            finally
            {
                lock (_refreshLock)
                {
                    _inFlightRefreshTask = null;
                }
            }
        }

        private void RecordTrace(ApiRequest request, HttpRawResponse response, bool wasRetried)
        {
            var entry = new ApiTraceEntry
            {
                timestampUtc = DateTime.UtcNow.ToString("O", CultureInfo.InvariantCulture),
                requestId = GetRequestId(request, response),
                method = request.Method,
                url = request.Url,
                statusCode = response.StatusCode,
                durationMs = response.DurationMs,
                succeeded = response.IsSuccess,
                wasRetried = wasRetried,
                requestBodyPreview = Truncate(SanitizeBody(request.JsonBody), 280),
                responseBodyPreview = Truncate(response.Body, 400)
            };

            _traces.Add(entry);
            if (_traces.Count > _maxTraces)
            {
                _traces.RemoveAt(0);
            }

            OnRequestTraced?.Invoke(entry);
        }

        private static ApiError ParseError(ApiRequest req, HttpRawResponse raw)
        {
            string reqId = GetRequestId(req, raw);
            int retryAfter = 0;
            if (raw.Headers.TryGetValue("Retry-After", out string ra) && int.TryParse(ra, out int raVal))
            {
                retryAfter = raVal;
            }

            if (!string.IsNullOrWhiteSpace(raw.Body))
            {
                try
                {
                    var env = JsonUtility.FromJson<ApiError>(raw.Body);
                    if (env != null && (!string.IsNullOrEmpty(env.errorCode) || !string.IsNullOrEmpty(env.message)))
                    {
                        env.statusCode = raw.StatusCode;
                        if (string.IsNullOrEmpty(env.requestId)) env.requestId = reqId;
                        if (env.retryAfterSeconds <= 0) env.retryAfterSeconds = retryAfter;
                        return env;
                    }
                }
                catch
                {
                    // Fallback to generic HTTP error envelope below
                }
            }

            string code = raw.IsNetworkError ? "NETWORK_ERROR" : $"HTTP_{raw.StatusCode}";
            string message = !string.IsNullOrWhiteSpace(raw.ErrorText)
                ? raw.ErrorText
                : (!string.IsNullOrWhiteSpace(raw.Body) ? Truncate(raw.Body, 200) : $"HTTP {raw.StatusCode}");

            return ApiError.Create(raw.StatusCode, code, message, reqId, retryAfter);
        }

        private static string GetRequestId(ApiRequest req, HttpRawResponse resp)
        {
            if (resp != null && resp.Headers.TryGetValue("X-Request-Id", out string rId)) return rId;
            if (req != null && req.Headers.TryGetValue("X-Request-Id", out string qId)) return qId;
            return string.Empty;
        }

        private static string SanitizeBody(string body)
        {
            if (string.IsNullOrEmpty(body)) return string.Empty;
            if (body.IndexOf("\"password\"", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                return "{\"redacted\":true,\"reason\":\"contains password\"}";
            }
            return body;
        }

        private static string Truncate(string s, int max)
        {
            if (string.IsNullOrEmpty(s)) return string.Empty;
            return s.Length <= max ? s : s.Substring(0, max) + "...";
        }
    }
}
