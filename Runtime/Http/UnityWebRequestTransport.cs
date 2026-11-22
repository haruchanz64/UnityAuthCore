using System;
using System.Diagnostics;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using UnityAuthCore.Core;
using UnityEngine.Networking;

namespace UnityAuthCore.Http
{
    /// <summary>
    /// Default live HTTP/HTTPS transport powered by <see cref="UnityWebRequest"/>.
    /// </summary>
    public sealed class UnityWebRequestTransport : IHttpTransport
    {
        /// <summary>
        /// Dispatches <paramref name="request"/> using <see cref="UnityWebRequest"/>, setting JSON headers and aborting on cancellation.
        /// </summary>
        /// <param name="request">Outgoing request descriptor; timeout is clamped to at least 1 second.</param>
        /// <param name="ct">Cancellation token that aborts the active <see cref="UnityWebRequest"/> when triggered.</param>
        /// <returns>The raw HTTP status, response headers, body text, network-error flag, and elapsed duration in milliseconds.</returns>
        public async Task<HttpRawResponse> SendAsync(ApiRequest request, CancellationToken ct = default)
        {
            var sw = Stopwatch.StartNew();
            var result = new HttpRawResponse();

            using (var webRequest = new UnityWebRequest(request.Url, request.Method ?? "GET"))
            {
                webRequest.downloadHandler = new DownloadHandlerBuffer();
                webRequest.timeout = Math.Max(1, request.TimeoutSeconds);

                if (!string.IsNullOrEmpty(request.JsonBody))
                {
                    byte[] bodyBytes = Encoding.UTF8.GetBytes(request.JsonBody);
                    webRequest.uploadHandler = new UploadHandlerRaw(bodyBytes);
                    webRequest.SetRequestHeader("Content-Type", "application/json");
                }

                webRequest.SetRequestHeader("Accept", "application/json");

                foreach (var kvp in request.Headers)
                {
                    if (!string.IsNullOrEmpty(kvp.Key) && kvp.Value != null)
                    {
                        webRequest.SetRequestHeader(kvp.Key, kvp.Value);
                    }
                }

                var op = webRequest.SendWebRequest();
                using (ct.Register(() => webRequest.Abort()))
                {
                    while (!op.isDone)
                    {
                        ct.ThrowIfCancellationRequested();
                        await Task.Yield();
                    }
                }

                sw.Stop();
                result.DurationMs = sw.Elapsed.TotalMilliseconds;
                result.StatusCode = (int)webRequest.responseCode;
                result.Body = webRequest.downloadHandler != null ? webRequest.downloadHandler.text : string.Empty;
                result.IsNetworkError = webRequest.result == UnityWebRequest.Result.ConnectionError ||
                                        webRequest.result == UnityWebRequest.Result.DataProcessingError;
                result.ErrorText = webRequest.error;

                var respHeaders = webRequest.GetResponseHeaders();
                if (respHeaders != null)
                {
                    foreach (var h in respHeaders)
                    {
                        result.Headers[h.Key] = h.Value;
                    }
                }
            }

            return result;
        }
    }
}
