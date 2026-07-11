# UnityAuthCore Reference Auth Server (Optional)

Optional self-hosted reference backend implementing the [OpenAPI 3.0 contract](../Docs~/openapi.yaml). You can deploy it directly with Docker or replace it with any ASP.NET Core, Go, Node.js, Python, Supabase, or Firebase backend through `IAuthBackendAdapter`.

## Quick start with Docker

```bash
cp .env.example .env
docker compose up --build -d
```

Verify the container health endpoint:

```bash
curl http://localhost:8080/healthz
```

## Run locally with Node.js 22+

```bash
node src/server.mjs
```

## Implemented security behaviors

- `scrypt` salted password hashing with constant-time verification
- HS256 JWT signing and verification (`iss`, `aud`, `exp`)
- Rotating refresh tokens with reuse-detection family revocation
- Sliding-window per-IP rate limiting returning `429` and `Retry-After`
- Dedicated game server token validation at `POST /v1/auth/introspect` protected by `X-Server-Key`
