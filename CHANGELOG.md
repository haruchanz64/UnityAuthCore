# Changelog

All notable changes to this package are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.1] - 2026-11-22

### Changed

- Expanded `README.md` into a full developer guide covering architecture, quick start, verified C# code examples, core API and extension contracts, included samples, EditMode test coverage, and troubleshooting caveats.
- Added XML documentation comments across all public and non-trivial helper symbols in `Runtime/`, `Editor/`, and `Samples~/`.
- Added JSDoc comments for all functions in `Server~/src/server.mjs`.

## [1.0.0] - 2026-07-11

### Added

- Backend-agnostic framework contracts (`IAuthBackendAdapter`, `IHttpTransport`, `IApiInterceptor`, `IRetryPolicy`, `ITokenStore`, `IServerTokenValidator`) and `AuthFrameworkConfig` ScriptableObject.
- `ApiHttpClient` with `UnityWebRequestTransport`, `BearerAuthInterceptor`, `RequestIdInterceptor`, `ExponentialBackoffRetryPolicy` (`429` / `5xx` with `Retry-After`), live trace capture, and single-flight `401` token refresh coalescing.
- `RestAuthBackendAdapter` with configurable `RestEndpointMap` and `MockAuthTransport` in-process HS256 JWT server with refresh-token rotation and reuse-detection family revocation.
- `JwtUtility` (Base64Url, claims decoding, HS256 signing, constant-time verification) and `EncryptedFileTokenStore` (AES-256-CBC + Encrypt-then-MAC HMAC-SHA256).
- `AuthClient` session manager and drop-in `AccountController` MonoBehaviour with Inspector `UnityEvent` hooks and custom adapter injection.
- `MultiplayerAuthBridge` (`MultiplayerAuthTicket`, `LocalHs256JwtValidator`, `RemoteIntrospectionValidator`, duplicate-login registry) compatible with Netcode for GameObjects, Mirror, and FishNet.
- UI Toolkit `AuthWorkbenchWindow` (`Tools > UnityAuthCore > Auth & API Console`) with Session & Auth Flows, JWT & Refresh Lab, Multiplayer Handshake, and HTTP API Trace tabs, plus custom `AuthFrameworkConfigInspector`.
- OpenAPI 3.0.3 contract (`Docs~/openapi.yaml`) and optional Dockerized Node.js 22 LTS reference server (`Server~/Dockerfile`, `Server~/docker-compose.yml`, `Server~/src/server.mjs`).
- Starter samples in `Samples~/BackendAdapters` (Supabase and Firebase) and `Samples~/MultiplayerAdapters`.
- EditMode NUnit test suite in `Tests/Editor/UnityAuthCoreTests.cs`.
