using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using NUnit.Framework;
using UnityAuthCore.Backends;
using UnityAuthCore.Components;
using UnityAuthCore.Core;
using UnityAuthCore.Engine;
using UnityAuthCore.Http;
using UnityAuthCore.Multiplayer;
using UnityAuthCore.Security;
using UnityEngine;

namespace UnityAuthCore.Tests
{
    public sealed class UnityAuthCoreTests
    {
        private sealed class FakeCustomAdapter : IAuthBackendAdapter
        {
            public string ProviderId => "custom_playfab_stub";
            public bool LoginCalled { get; private set; }

            public Task<AuthResult<AuthSession>> SignInGuestAsync(string deviceId, string displayName = null, CancellationToken ct = default) =>
                Task.FromResult(AuthResult<AuthSession>.Ok(MakeSession("guest_custom", isGuest: true)));

            public Task<AuthResult<AuthSession>> RegisterAsync(string email, string password, string displayName = null, CancellationToken ct = default) =>
                Task.FromResult(AuthResult<AuthSession>.Ok(MakeSession("reg_custom", isGuest: false)));

            public Task<AuthResult<AuthSession>> LoginAsync(string email, string password, CancellationToken ct = default)
            {
                LoginCalled = true;
                return Task.FromResult(AuthResult<AuthSession>.Ok(MakeSession("login_custom", isGuest: false)));
            }

            public Task<AuthResult<AuthSession>> RefreshAsync(string refreshToken, CancellationToken ct = default) =>
                Task.FromResult(AuthResult<AuthSession>.Ok(MakeSession("refreshed_custom", isGuest: false)));

            public Task<AuthResult<bool>> LogoutAsync(string accessToken, string refreshToken, CancellationToken ct = default) =>
                Task.FromResult(AuthResult<bool>.Ok(true, 204));

            public Task<AuthResult<AuthUserProfile>> GetProfileAsync(CancellationToken ct = default) =>
                Task.FromResult(AuthResult<AuthUserProfile>.Ok(new AuthUserProfile { accountId = "acc_custom", displayName = "CustomHero" }));

            public Task<AuthResult<AuthUserProfile>> UpdateProfileAsync(AuthProfileUpdateRequest update, CancellationToken ct = default) =>
                Task.FromResult(AuthResult<AuthUserProfile>.Ok(new AuthUserProfile { accountId = "acc_custom", displayName = update.displayName }));

            public Task<AuthResult<AuthSession>> LinkEmailPasswordAsync(string email, string password, CancellationToken ct = default) =>
                Task.FromResult(AuthResult<AuthSession>.Ok(MakeSession("linked_custom", isGuest: false)));

            public Task<AuthResult<TokenValidationResult>> IntrospectTokenAsync(string accessToken, string serverApiKey = null, CancellationToken ct = default) =>
                Task.FromResult(AuthResult<TokenValidationResult>.Ok(new TokenValidationResult { isValid = true, accountId = "acc_custom" }));

            private static AuthSession MakeSession(string token, bool isGuest)
            {
                return new AuthSession
                {
                    accessToken = token,
                    refreshToken = "rt_" + token,
                    expiresAtUnixSeconds = DateTimeOffset.UtcNow.ToUnixTimeSeconds() + 3600,
                    providerId = "custom_playfab_stub",
                    user = new AuthUserProfile { accountId = "acc_custom", displayName = "CustomHero", isGuest = isGuest }
                };
            }
        }

        [Test]
        public async Task GuestSignIn_UpgradeToEmail_AndUpdateProfile_WorksEndToEnd()
        {
            var client = AuthClient.CreateMock(out _);

            var guestRes = await client.SignInGuestAsync("device_abc", "Wanderer");
            Assert.IsTrue(guestRes.Succeeded);
            Assert.IsTrue(guestRes.Data.user.isGuest);
            string originalAccountId = guestRes.Data.user.accountId;

            var upgradeRes = await client.UpgradeGuestWithEmailAsync("hero@example.com", "Secret123");
            Assert.IsTrue(upgradeRes.Succeeded);
            Assert.AreEqual(originalAccountId, upgradeRes.Data.user.accountId);
            Assert.IsFalse(upgradeRes.Data.user.isGuest);
            Assert.AreEqual("hero@example.com", upgradeRes.Data.user.email);

            var profileRes = await client.UpdateProfileAsync(new AuthProfileUpdateRequest { displayName = "KnightNova" });
            Assert.IsTrue(profileRes.Succeeded);
            Assert.AreEqual("KnightNova", profileRes.Data.displayName);
            Assert.AreEqual("KnightNova", client.CurrentSession.user.displayName);
        }

        [Test]
        public async Task Register_DuplicateEmailReturns409_AndBadPasswordReturns401()
        {
            var client = AuthClient.CreateMock(out _);

            var reg1 = await client.RegisterAsync("alice@example.com", "StrongPass1", "Alice");
            Assert.IsTrue(reg1.Succeeded);
            Assert.AreEqual(201, reg1.StatusCode);

            var reg2 = await client.RegisterAsync("alice@example.com", "StrongPass1", "Alice2");
            Assert.IsFalse(reg2.Succeeded);
            Assert.AreEqual(409, reg2.StatusCode);
            Assert.AreEqual("EMAIL_ALREADY_EXISTS", reg2.Error.errorCode);

            var badLogin = await client.LoginAsync("alice@example.com", "WrongPass");
            Assert.IsFalse(badLogin.Succeeded);
            Assert.AreEqual(401, badLogin.StatusCode);
            Assert.AreEqual("INVALID_CREDENTIALS", badLogin.Error.errorCode);
        }

        [Test]
        public async Task ConcurrentUnauthorizedCalls_TriggerSingleFlightRefreshExactlyOnce()
        {
            var client = AuthClient.CreateMock(out MockAuthTransport mock);
            mock.SimulatedLatencyMs = 25;

            var login = await client.SignInGuestAsync("device_sf", "Pilot");
            Assert.IsTrue(login.Succeeded);

            // Corrupt access token so all 3 concurrent protected calls fail with 401
            client.CurrentSession.accessToken = "corrupted.expired.jwt";
            int hitsBefore = mock.RefreshEndpointHits;

            var t1 = client.Adapter.GetProfileAsync();
            var t2 = client.Adapter.GetProfileAsync();
            var t3 = client.Adapter.GetProfileAsync();
            var results = await Task.WhenAll(t1, t2, t3);

            Assert.IsTrue(results[0].Succeeded);
            Assert.IsTrue(results[1].Succeeded);
            Assert.IsTrue(results[2].Succeeded);
            Assert.AreEqual(1, mock.RefreshEndpointHits - hitsBefore);
        }

        [Test]
        public async Task RefreshTokenReuseDetection_RevokesEntireSessionFamily()
        {
            var client = AuthClient.CreateMock(out _);

            var login = await client.SignInGuestAsync("device_rot", "Scout");
            Assert.IsTrue(login.Succeeded);
            string firstRefresh = login.Data.refreshToken;

            var refresh1 = await client.RefreshSessionAsync();
            Assert.IsTrue(refresh1.Succeeded);
            string secondRefresh = refresh1.Data.refreshToken;
            Assert.AreNotEqual(firstRefresh, secondRefresh);

            // Replaying first (already consumed) refresh token triggers reuse detection and revokes the family
            var replay = await client.Adapter.RefreshAsync(firstRefresh);
            Assert.IsFalse(replay.Succeeded);
            Assert.AreEqual("REFRESH_TOKEN_REUSE_DETECTED", replay.Error.errorCode);

            // Now even the newer second refresh token in that same family must be rejected
            var followUp = await client.Adapter.RefreshAsync(secondRefresh);
            Assert.IsFalse(followUp.Succeeded);
            Assert.AreEqual("REFRESH_TOKEN_REVOKED", followUp.Error.errorCode);
        }

        [Test]
        public void JwtUtility_SignsVerifiesAndRejectsTamperedOrExpiredTokens()
        {
            DateTime now = new DateTime(2026, 11, 24, 12, 0, 0, DateTimeKind.Utc);
            long nowUnix = new DateTimeOffset(now).ToUnixTimeSeconds();
            const string secret = "unit-test-secret-key-32-chars-minimum";

            var claims = new JwtClaims
            {
                sub = "acc_12345",
                iss = "test-iss",
                aud = "test-aud",
                displayName = "Tester",
                iat = nowUnix,
                exp = nowUnix + 60
            };

            string jwt = JwtUtility.CreateHs256Token(claims, secret);
            Assert.IsTrue(JwtUtility.TryParseClaims(jwt, out JwtClaims parsed, out _));
            Assert.AreEqual("acc_12345", parsed.sub);

            var valid = JwtUtility.VerifyHs256(jwt, secret, "test-iss", "test-aud", clockSkewSeconds: 0, utcNow: now.AddSeconds(30));
            Assert.IsTrue(valid.isValid);
            Assert.AreEqual("acc_12345", valid.accountId);

            // Tamper last char
            string tampered = jwt.Substring(0, jwt.Length - 1) + (jwt[jwt.Length - 1] == 'A' ? 'B' : 'A');
            var badSig = JwtUtility.VerifyHs256(tampered, secret, "test-iss", "test-aud", clockSkewSeconds: 0, utcNow: now);
            Assert.IsFalse(badSig.isValid);
            Assert.AreEqual("SIGNATURE_INVALID", badSig.failureCode);

            // Expired
            var expired = JwtUtility.VerifyHs256(jwt, secret, "test-iss", "test-aud", clockSkewSeconds: 0, utcNow: now.AddSeconds(120));
            Assert.IsFalse(expired.isValid);
            Assert.AreEqual("TOKEN_EXPIRED", expired.failureCode);
        }

        [Test]
        public async Task EncryptedFileTokenStore_PersistsSessionAndRejectsTamperedFile()
        {
            string tempFile = Path.Combine(Path.GetTempPath(), $"uac_test_{Guid.NewGuid():N}.dat");
            try
            {
                var store = new EncryptedFileTokenStore(tempFile, "test-passphrase-123");
                var session = new AuthSession
                {
                    accessToken = "jwt_abc",
                    refreshToken = "rt_xyz",
                    expiresAtUnixSeconds = 9999999999,
                    user = new AuthUserProfile { accountId = "acc_99", displayName = "Cipher" }
                };

                await store.SaveAsync(session);
                Assert.IsTrue(File.Exists(tempFile));

                var loaded = await store.LoadAsync();
                Assert.IsNotNull(loaded);
                Assert.AreEqual("jwt_abc", loaded.accessToken);
                Assert.AreEqual("acc_99", loaded.user.accountId);

                // Flip a byte in the file to verify Encrypt-then-MAC tamper detection
                byte[] bytes = File.ReadAllBytes(tempFile);
                bytes[bytes.Length - 1] ^= 0xFF;
                File.WriteAllBytes(tempFile, bytes);

                var corrupted = await store.LoadAsync();
                Assert.IsNull(corrupted);
            }
            finally
            {
                if (File.Exists(tempFile)) File.Delete(tempFile);
            }
        }

        [Test]
        public async Task MultiplayerAuthBridge_ValidatesTicketsViaLocalHs256AndRemoteIntrospect()
        {
            var client = AuthClient.CreateMock(out MockAuthTransport mock);
            var login = await client.SignInGuestAsync("mp_dev_1", "SquadLead");
            Assert.IsTrue(login.Succeeded);

            byte[] payload = MultiplayerAuthBridge.BuildClientConnectionPayload(login.Data, "1.2.0");
            var bridge = new MultiplayerAuthBridge
            {
                RequiredClientVersion = "1.2.0",
                RejectDuplicateAccountLogin = true
            };

            // 1. Validate with fast offline LocalHs256JwtValidator
            var localValidator = new LocalHs256JwtValidator(mock.JwtSecret, mock.Issuer, mock.Audience);
            var approval1 = await bridge.ApproveConnectionAsync(100, payload, localValidator);
            Assert.IsTrue(approval1.Approved);
            Assert.AreEqual(login.Data.user.accountId, approval1.Identity.accountId);
            Assert.AreEqual(1, bridge.ActivePlayerCount);

            // 2. Duplicate login rejected when RejectDuplicateAccountLogin = true
            var dupApproval = await bridge.ApproveConnectionAsync(101, payload, localValidator);
            Assert.IsFalse(dupApproval.Approved);
            Assert.AreEqual("ACCOUNT_ALREADY_CONNECTED", dupApproval.RejectionCode);

            // 3. Disconnect client 100, then verify RemoteIntrospectionValidator works too
            bridge.HandleClientDisconnected(100);
            Assert.AreEqual(0, bridge.ActivePlayerCount);

            var remoteValidator = new RemoteIntrospectionValidator(client.Adapter);
            var approval2 = await bridge.ApproveConnectionAsync(102, payload, remoteValidator);
            Assert.IsTrue(approval2.Approved);
            Assert.AreEqual(login.Data.user.accountId, approval2.Identity.accountId);
        }

        [Test]
        public async Task RetryPolicy_RetriesTransient429AndRecovers()
        {
            var mock = new MockAuthTransport { ForceNextRequests429Count = 1 };
            var retry = new ExponentialBackoffRetryPolicy(maxRetries: 2, baseDelayMs: 10, maxDelayMs: 50);
            var http = new ApiHttpClient(mock, retry);
            var adapter = new RestAuthBackendAdapter(http, "http://mock.local");
            var client = new AuthClient(adapter, http);

            var res = await client.SignInGuestAsync("retry_dev", "Resilient");
            Assert.IsTrue(res.Succeeded);
            Assert.AreEqual(2, mock.TotalRequestsHandled);
        }

        [Test]
        public async Task AccountController_SupportsCustomAdapterInjectionAndFiresUnityEvents()
        {
            var go = new GameObject("AccountControllerTestHost");
            try
            {
                var controller = go.AddComponent<AccountController>();
                var customAdapter = new FakeCustomAdapter();
                controller.ConfigureCustomAdapter(customAdapter);

                AuthSession signedInSession = null;
                bool signedOutFired = false;
                controller.onSignedIn.AddListener(s => signedInSession = s);
                controller.onSignedOut.AddListener(() => signedOutFired = true);

                var loginRes = await controller.LoginAsync("dev@custom.io", "pass123");
                Assert.IsTrue(loginRes.Succeeded);
                Assert.IsTrue(customAdapter.LoginCalled);
                Assert.IsNotNull(signedInSession);
                Assert.AreEqual("custom_playfab_stub", signedInSession.providerId);

                byte[] mpPayload = controller.BuildMultiplayerConnectionPayload();
                Assert.Greater(mpPayload.Length, 10);

                await controller.SignOutAsync();
                Assert.IsTrue(signedOutFired);
            }
            finally
            {
                UnityEngine.Object.DestroyImmediate(go);
            }
        }
    }
}
