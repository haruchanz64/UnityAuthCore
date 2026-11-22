using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using UnityAuthCore.Backends;
using UnityAuthCore.Config;
using UnityAuthCore.Core;
using UnityAuthCore.Engine;
using UnityAuthCore.Http;
using UnityAuthCore.Multiplayer;
using UnityAuthCore.Security;
using UnityEditor;
using UnityEditor.UIElements;
using UnityEngine;
using UnityEngine.UIElements;

namespace UnityAuthCore.Editor.UI
{
    /// <summary>
    /// Four-tab UI Toolkit Editor workbench for exercising authentication flows, inspecting JWT claims,
    /// testing single-flight 401 token refresh, verifying multiplayer handshake tickets, and reviewing HTTP traces.
    /// </summary>
    public sealed class AuthWorkbenchWindow : EditorWindow
    {
        private enum Tab { Session, JwtLab, Multiplayer, ApiTrace }

        private Tab _activeTab = Tab.Session;
        private AuthFrameworkConfig _configAsset;
        private AuthBackendMode _sandboxMode = AuthBackendMode.MockInProcess;
        private string _sandboxBaseUrl = "http://localhost:8080";
        private string _sandboxSecret = "dev-local-mock-secret-change-in-production-32bytes";

        private AuthClient _client;
        private MockAuthTransport _mockTransport;
        private readonly MultiplayerAuthBridge _mpBridge = new MultiplayerAuthBridge();

        private string _emailInput = "player@example.com";
        private string _passwordInput = "Passw0rd!";
        private string _displayNameInput = "NovaPilot";
        private string _lastStatusMessage = "Ready. Use Mock mode or connect to a live REST/Docker backend.";
        private bool _lastStatusIsError;
        private string _lastMultiplayerReport = "No multiplayer handshake tested yet.";
        private string _lastSingleFlightReport = "Click 'Force Expire + Fire 3 Concurrent Calls' to test single-flight 401 refresh.";

        private VisualElement _body;
        private readonly List<Button> _tabButtons = new List<Button>();

        /// <summary>
        /// Opens or focuses the Auth and API Console Editor window in its default sandbox mode.
        /// </summary>
        [MenuItem("Tools/HaruChanZ64/Networking/UnityAuthCore/Auth and API Console", false, 146)]
        public static void OpenWindow()
        {
            var win = GetWindow<AuthWorkbenchWindow>("UnityAuthCore Console");
            win.minSize = new Vector2(380, 360);
            win.Show();
        }

        /// <summary>
        /// Opens or focuses the Auth and API Console prebound to <paramref name="config"/>.
        /// </summary>
        /// <param name="config">Framework configuration asset to bind to the console session.</param>
        public static void OpenWithConfig(AuthFrameworkConfig config)
        {
            var win = GetWindow<AuthWorkbenchWindow>("UnityAuthCore Console");
            win.minSize = new Vector2(380, 360);
            win._configAsset = config;
            win.RebuildClient();
            win.RebuildBody();
            win.Show();
        }

        private void OnEnable()
        {
            if (_client == null)
            {
                RebuildClient();
            }
        }

        /// <summary>
        /// Builds the root UI Toolkit layout including header, config selector, tab bar, and scrollable body.
        /// </summary>
        private void CreateGUI()
        {
            var root = rootVisualElement;
            root.Clear();
            root.AddToClassList("uac-root");

            var uss = AssetDatabase.LoadAssetAtPath<StyleSheet>(
                "Packages/com.haruchanz64.unity-auth-core/Editor/UI/AuthWorkbenchStyles.uss");
            if (uss != null) root.styleSheets.Add(uss);

            // Header
            var header = new VisualElement();
            header.AddToClassList("uac-header");

            var titleBox = new VisualElement();
            titleBox.style.flexGrow = 1;
            titleBox.style.flexShrink = 1;
            titleBox.style.minWidth = 180;
            titleBox.style.marginRight = 8;
            var title = new Label("UnityAuthCore — Auth & API Console");
            title.AddToClassList("uac-title");
            var sub = new Label("Backend-Agnostic Auth Framework | Single-Flight 401 Refresh | Multiplayer Ticket Verifier");
            sub.AddToClassList("uac-subtitle");
            titleBox.Add(title);
            titleBox.Add(sub);

            var cfgField = new ObjectField("Config Asset") { objectType = typeof(AuthFrameworkConfig), value = _configAsset };
            cfgField.style.flexGrow = 1;
            cfgField.style.minWidth = 200;
            cfgField.style.maxWidth = 340;
            cfgField.RegisterValueChangedCallback(evt =>
            {
                _configAsset = evt.newValue as AuthFrameworkConfig;
                RebuildClient();
                RebuildBody();
            });

            header.Add(titleBox);
            header.Add(cfgField);
            root.Add(header);

            // Tabs
            var tabs = new VisualElement();
            tabs.AddToClassList("uac-tabs");
            _tabButtons.Clear();
            AddTabButton(tabs, "1. Session & Auth Flows", Tab.Session);
            AddTabButton(tabs, "2. JWT & Refresh Lab", Tab.JwtLab);
            AddTabButton(tabs, "3. Multiplayer Handshake", Tab.Multiplayer);
            AddTabButton(tabs, "4. HTTP API Trace", Tab.ApiTrace);
            root.Add(tabs);

            var scroll = new ScrollView();
            scroll.style.flexGrow = 1;
            scroll.style.minHeight = 0;
            _body = new VisualElement();
            scroll.Add(_body);
            root.Add(scroll);

            UpdateTabStyles();
            RebuildBody();
        }

        /// <summary>
        /// Creates a navigation tab button, registers its click handler, and appends it to <paramref name="parent"/>.
        /// </summary>
        private void AddTabButton(VisualElement parent, string text, Tab tab)
        {
            var btn = new Button(() =>
            {
                _activeTab = tab;
                UpdateTabStyles();
                RebuildBody();
            }) { text = text };
            btn.AddToClassList("uac-tab");
            btn.userData = tab;
            _tabButtons.Add(btn);
            parent.Add(btn);
        }

        /// <summary>
        /// Updates active CSS classes across the tab strip to match <see cref="_activeTab"/>.
        /// </summary>
        private void UpdateTabStyles()
        {
            for (int i = 0; i < _tabButtons.Count; i++)
            {
                bool active = (Tab)_tabButtons[i].userData == _activeTab;
                _tabButtons[i].EnableInClassList("uac-tab--active", active);
            }
        }

        /// <summary>
        /// Reconstructs <see cref="_client"/> using <see cref="_configAsset"/> when assigned or the local sandbox settings,
        /// always backed by an <see cref="InMemoryTokenStore"/> so console tests do not overwrite game session files.
        /// </summary>
        private void RebuildClient()
        {
            _mockTransport = null;
            if (_configAsset != null)
            {
                if (_configAsset.backendMode == AuthBackendMode.MockInProcess)
                {
                    _client = AuthClient.CreateMock(out _mockTransport, new InMemoryTokenStore());
                    _mockTransport.JwtSecret = _configAsset.serverHs256Secret;
                    _mockTransport.Issuer = _configAsset.expectedIssuer;
                    _mockTransport.Audience = _configAsset.expectedAudience;
                }
                else
                {
                    _client = _configAsset.CreateClient(customStore: new InMemoryTokenStore());
                }
            }
            else if (_sandboxMode == AuthBackendMode.RestEndpoint)
            {
                var http = new ApiHttpClient(new UnityWebRequestTransport());
                var adapter = new RestAuthBackendAdapter(http, _sandboxBaseUrl);
                _client = new AuthClient(adapter, http, new InMemoryTokenStore());
            }
            else
            {
                _client = AuthClient.CreateMock(out _mockTransport, new InMemoryTokenStore());
                _mockTransport.JwtSecret = _sandboxSecret;
            }
        }

        /// <summary>
        /// Clears and repopulates the active tab body panel.
        /// </summary>
        private void RebuildBody()
        {
            if (_body == null) return;
            _body.Clear();
            if (_client == null) RebuildClient();

            switch (_activeTab)
            {
                case Tab.Session: BuildSessionTab(); break;
                case Tab.JwtLab: BuildJwtLabTab(); break;
                case Tab.Multiplayer: BuildMultiplayerTab(); break;
                case Tab.ApiTrace: BuildApiTraceTab(); break;
            }
        }

        /// <summary>
        /// Populates Tab 1 with backend target controls, current session summary, and account action buttons.
        /// </summary>
        private void BuildSessionTab()
        {
            // Target selector when no Config Asset is assigned
            if (_configAsset == null)
            {
                var targetCard = MakeCard("Backend Target (Sandbox)");
                var modeField = new EnumField("Mode", _sandboxMode);
                modeField.RegisterValueChangedCallback(evt =>
                {
                    _sandboxMode = (AuthBackendMode)evt.newValue;
                    RebuildClient();
                    RebuildBody();
                });
                targetCard.Add(modeField);

                if (_sandboxMode == AuthBackendMode.RestEndpoint)
                {
                    var urlField = new TextField("REST Base URL") { value = _sandboxBaseUrl };
                    urlField.RegisterValueChangedCallback(evt => _sandboxBaseUrl = evt.newValue);
                    var applyBtn = MakeBtn("Reconnect Client", "uac-btn--accent", () =>
                    {
                        RebuildClient();
                        SetStatus($"Client configured for {_sandboxBaseUrl}", isError: false);
                    });
                    targetCard.Add(urlField);
                    targetCard.Add(applyBtn);
                }
                _body.Add(targetCard);
            }

            // Status Banner
            var statusCard = MakeCard("Current Session State");
            var statusLbl = new Label(_lastStatusMessage);
            statusLbl.AddToClassList(_lastStatusIsError ? "uac-status-err" : "uac-status-ok");
            statusLbl.style.whiteSpace = WhiteSpace.Normal;
            statusCard.Add(statusLbl);

            if (_client.IsSignedIn)
            {
                var s = _client.CurrentSession;
                statusCard.Add(new Label($"Account ID: {s.user?.accountId}   |   Display Name: {s.user?.displayName}   |   Guest: {s.user?.isGuest}"));
                statusCard.Add(new Label($"Email: {(string.IsNullOrEmpty(s.user?.email) ? "(none)" : s.user.email)}   |   Roles: {string.Join(", ", s.user?.roles ?? new List<string>())}"));
                statusCard.Add(new Label($"Access TTL Remaining: {s.GetRemainingSeconds()}s   |   Provider: {s.providerId}"));
            }
            else
            {
                var signedOut = new Label("Not signed in.");
                signedOut.AddToClassList("uac-muted");
                statusCard.Add(signedOut);
            }
            _body.Add(statusCard);

            // Credentials & Actions
            var formCard = MakeCard("Account Actions");
            var emailField = new TextField("Email") { value = _emailInput };
            emailField.RegisterValueChangedCallback(e => _emailInput = e.newValue);
            var passField = new TextField("Password") { value = _passwordInput, isPasswordField = true };
            passField.RegisterValueChangedCallback(e => _passwordInput = e.newValue);
            var nameField = new TextField("Display Name") { value = _displayNameInput };
            nameField.RegisterValueChangedCallback(e => _displayNameInput = e.newValue);

            formCard.Add(emailField);
            formCard.Add(passField);
            formCard.Add(nameField);

            var row1 = new VisualElement();
            row1.AddToClassList("uac-row");
            row1.Add(MakeBtn("Sign In Guest", "uac-btn--accent", () => RunAsync(async () =>
            {
                var r = await _client.SignInGuestAsync("editor-device-01", _displayNameInput);
                ReportResult("Guest sign-in", r);
            })));
            row1.Add(MakeBtn("Register Email", "uac-btn--primary", () => RunAsync(async () =>
            {
                var r = await _client.RegisterAsync(_emailInput, _passwordInput, _displayNameInput);
                ReportResult("Register", r);
            })));
            row1.Add(MakeBtn("Login Email", "uac-btn--primary", () => RunAsync(async () =>
            {
                var r = await _client.LoginAsync(_emailInput, _passwordInput);
                ReportResult("Login", r);
            })));
            formCard.Add(row1);

            var row2 = new VisualElement();
            row2.AddToClassList("uac-row");
            row2.Add(MakeBtn("Upgrade Guest -> Email", "uac-btn--accent", () => RunAsync(async () =>
            {
                var r = await _client.UpgradeGuestWithEmailAsync(_emailInput, _passwordInput);
                ReportResult("Guest upgrade", r);
            })));
            row2.Add(MakeBtn("Update Display Name", null, () => RunAsync(async () =>
            {
                var r = await _client.UpdateProfileAsync(new AuthProfileUpdateRequest { displayName = _displayNameInput });
                ReportResult("Profile update", r);
            })));
            row2.Add(MakeBtn("Fetch /v1/account/me", null, () => RunAsync(async () =>
            {
                var r = await _client.GetProfileAsync();
                ReportResult("GetProfile", r);
            })));
            row2.Add(MakeBtn("Sign Out", "uac-btn--danger", () => RunAsync(async () =>
            {
                var r = await _client.SignOutAsync();
                ReportResult("Sign out", r);
            })));
            formCard.Add(row2);

            _body.Add(formCard);
        }

        /// <summary>
        /// Populates Tab 2 with decoded JWT claims and controls to test manual and single-flight 401 refresh.
        /// </summary>
        private void BuildJwtLabTab()
        {
            var jwtCard = MakeCard("Decoded Access JWT Claims");
            if (!_client.IsSignedIn)
            {
                jwtCard.Add(new Label("Sign in on Tab 1 first to inspect live JWT claims."));
            }
            else if (_client.TryDecodeCurrentClaims(out JwtClaims claims, out string err))
            {
                jwtCard.Add(new Label($"Subject (sub): {claims.sub}"));
                jwtCard.Add(new Label($"Issuer (iss): {claims.iss}   |   Audience (aud): {claims.aud}"));
                jwtCard.Add(new Label($"Issued (iat): {claims.iat}   |   Expires (exp): {claims.exp}   |   Expired: {claims.IsExpired()}"));
                jwtCard.Add(new Label($"Roles: {string.Join(", ", claims.roles)}"));
                var rawLbl = new Label($"Payload JSON:\n{claims.rawPayloadJson}");
                rawLbl.AddToClassList("uac-mono");
                jwtCard.Add(rawLbl);
            }
            else
            {
                jwtCard.Add(new Label($"Opaque / non-JWT access token: {err}"));
            }
            _body.Add(jwtCard);

            var sfCard = MakeCard("Single-Flight 401 Refresh Lab");
            var row = new VisualElement();
            row.AddToClassList("uac-row");
            row.Add(MakeBtn("Manual Refresh", "uac-btn--accent", () => RunAsync(async () =>
            {
                var r = await _client.RefreshSessionAsync();
                ReportResult("Manual refresh", r);
            })));
            row.Add(MakeBtn("Force Expire + Fire 3 Concurrent Calls", "uac-btn--primary", () => RunAsync(async () =>
            {
                if (!_client.IsSignedIn)
                {
                    _lastSingleFlightReport = "Sign in first before running the single-flight 401 test.";
                    RebuildBody();
                    return;
                }

                int hitsBefore = _mockTransport != null ? _mockTransport.RefreshEndpointHits : 0;
                // Corrupt access token directly so the server returns 401 on all 3 concurrent protected calls
                _client.CurrentSession.accessToken = "expired.invalid.token";
                var t1 = _client.Adapter.GetProfileAsync();
                var t2 = _client.Adapter.GetProfileAsync();
                var t3 = _client.Adapter.GetProfileAsync();
                var results = await Task.WhenAll(t1, t2, t3);

                int okCount = 0;
                for (int i = 0; i < results.Length; i++) if (results[i].Succeeded) okCount++;
                int refreshDelta = _mockTransport != null ? _mockTransport.RefreshEndpointHits - hitsBefore : -1;

                _lastSingleFlightReport = refreshDelta >= 0
                    ? $"3 concurrent calls completed: {okCount}/3 succeeded. /v1/auth/refresh hit {refreshDelta} time(s) (expected 1)."
                    : $"3 concurrent calls completed: {okCount}/3 succeeded. Check Tab 4 (HTTP API Trace) to inspect refresh coalescing.";
                RebuildBody();
            })));
            sfCard.Add(row);

            var reportLbl = new Label(_lastSingleFlightReport);
            reportLbl.AddToClassList("uac-mono");
            sfCard.Add(reportLbl);
            _body.Add(sfCard);
        }

        /// <summary>
        /// Populates Tab 3 with controls for testing multiplayer ticket serialization and server validation.
        /// </summary>
        private void BuildMultiplayerTab()
        {
            var mpCard = MakeCard("Dedicated Server / Host Connection Approval Tester");
            var info = new Label("Serializes the active session into MultiplayerAuthTicket UTF-8 bytes (for NGO ConnectionData, Mirror, or FishNet) and verifies it as a Dedicated Server.");
            info.AddToClassList("uac-muted");
            mpCard.Add(info);

            var secretField = new TextField("Server HS256 Secret") { value = _configAsset != null ? _configAsset.serverHs256Secret : _sandboxSecret };
            secretField.RegisterValueChangedCallback(e => _sandboxSecret = e.newValue);
            mpCard.Add(secretField);

            var row = new VisualElement();
            row.AddToClassList("uac-row");
            row.Add(MakeBtn("Validate via Local HS256", "uac-btn--primary", () => RunAsync(async () =>
            {
                await RunMultiplayerTest(useRemoteIntrospect: false);
            })));
            row.Add(MakeBtn("Validate via /v1/auth/introspect", "uac-btn--accent", () => RunAsync(async () =>
            {
                await RunMultiplayerTest(useRemoteIntrospect: true);
            })));
            row.Add(MakeBtn("Clear Connected Clients", null, () =>
            {
                _mpBridge.Clear();
                _lastMultiplayerReport = "Cleared active multiplayer session registry.";
                RebuildBody();
            }));
            mpCard.Add(row);

            var outLbl = new Label(_lastMultiplayerReport);
            outLbl.AddToClassList("uac-mono");
            mpCard.Add(outLbl);
            _body.Add(mpCard);
        }

        /// <summary>
        /// Builds a connection ticket from the active session and runs <see cref="MultiplayerAuthBridge.ApproveConnectionAsync"/>
        /// using either local HS256 verification or remote token introspection.
        /// </summary>
        private async Task RunMultiplayerTest(bool useRemoteIntrospect)
        {
            if (!_client.IsSignedIn)
            {
                _lastMultiplayerReport = "Not signed in. Sign in on Tab 1 first.";
                RebuildBody();
                return;
            }

            byte[] payload = MultiplayerAuthBridge.BuildClientConnectionPayload(_client.CurrentSession, "1.0.0");
            IServerTokenValidator validator = useRemoteIntrospect
                ? (IServerTokenValidator)new RemoteIntrospectionValidator(_client.Adapter)
                : new LocalHs256JwtValidator(
                    _configAsset != null ? _configAsset.serverHs256Secret : _sandboxSecret,
                    _configAsset != null ? _configAsset.expectedIssuer : "unity-auth-core-mock",
                    _configAsset != null ? _configAsset.expectedAudience : "unity-game-client");

            ulong clientId = (ulong)(_mpBridge.ActivePlayerCount + 1);
            var approval = await _mpBridge.ApproveConnectionAsync(clientId, payload, validator);

            _lastMultiplayerReport = approval.Approved
                ? $"APPROVED clientId={clientId} ({payload.Length} bytes) -> accountId={approval.Identity.accountId}, displayName={approval.Identity.displayName}, roles=[{string.Join(", ", approval.Identity.roles)}]"
                : $"REJECTED [{approval.RejectionCode}]: {approval.RejectionReason}";
            RebuildBody();
        }

        /// <summary>
        /// Populates Tab 4 with the reverse-chronological HTTP request trace log captured by <see cref="ApiHttpClient"/>.
        /// </summary>
        private void BuildApiTraceTab()
        {
            var card = MakeCard($"HTTP API Trace ({_client.HttpClient.Traces.Count} captured)");
            var row = new VisualElement();
            row.AddToClassList("uac-row");
            row.Add(MakeBtn("Refresh Trace", "uac-btn--accent", RebuildBody));
            row.Add(MakeBtn("Clear Trace", null, () =>
            {
                _client.HttpClient.ClearTraces();
                RebuildBody();
            }));
            card.Add(row);

            var traces = _client.HttpClient.Traces;
            if (traces.Count == 0)
            {
                card.Add(new Label("No HTTP requests traced yet."));
            }
            else
            {
                for (int i = traces.Count - 1; i >= 0; i--)
                {
                    var t = traces[i];
                    var item = new VisualElement();
                    item.AddToClassList("uac-trace-row");
                    if (!t.succeeded) item.AddToClassList("uac-trace-row--err");

                    var top = new Label($"[{t.statusCode}] {t.method} {t.url}  ({t.durationMs:F1} ms){(t.wasRetried ? " [RETRIED]" : string.Empty)}");
                    top.style.unityFontStyleAndWeight = FontStyle.Bold;
                    var reqIdLbl = new Label($"X-Request-Id: {t.requestId}   |   UTC: {t.timestampUtc}");
                    reqIdLbl.AddToClassList("uac-muted");
                    item.Add(top);
                    item.Add(reqIdLbl);

                    if (!string.IsNullOrEmpty(t.responseBodyPreview))
                    {
                        var respLbl = new Label($"Resp: {t.responseBodyPreview}");
                        respLbl.AddToClassList("uac-mono");
                        item.Add(respLbl);
                    }
                    card.Add(item);
                }
            }

            _body.Add(card);
        }

        /// <summary>
        /// Executes an async UI button callback and surfaces unhandled exceptions in the status banner.
        /// </summary>
        private async void RunAsync(Func<Task> action)
        {
            try
            {
                await action();
            }
            catch (Exception ex)
            {
                SetStatus($"Exception: {ex.Message}", isError: true);
            }
        }

        /// <summary>
        /// Formats an <see cref="AuthResult{T}"/> outcome into the session status banner.
        /// </summary>
        private void ReportResult<T>(string label, AuthResult<T> result)
        {
            if (result.Succeeded)
            {
                SetStatus($"{label} succeeded (HTTP {result.StatusCode}).", isError: false);
            }
            else
            {
                SetStatus($"{label} failed [{result.Error.errorCode} / HTTP {result.StatusCode}]: {result.Error.message}", isError: true);
            }
        }

        /// <summary>
        /// Updates the banner message and severity style, then refreshes the window body.
        /// </summary>
        private void SetStatus(string message, bool isError)
        {
            _lastStatusMessage = message;
            _lastStatusIsError = isError;
            RebuildBody();
        }

        /// <summary>
        /// Creates a styled card container with a section header label.
        /// </summary>
        private static VisualElement MakeCard(string title)
        {
            var card = new VisualElement();
            card.AddToClassList("uac-card");
            var lbl = new Label(title);
            lbl.AddToClassList("uac-card-title");
            card.Add(lbl);
            return card;
        }

        /// <summary>
        /// Creates a styled console button with an optional variant USS class.
        /// </summary>
        private static Button MakeBtn(string text, string variantClass, Action onClick)
        {
            var btn = new Button(onClick) { text = text };
            btn.AddToClassList("uac-btn");
            if (!string.IsNullOrEmpty(variantClass)) btn.AddToClassList(variantClass);
            return btn;
        }
    }
}
