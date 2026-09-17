# Private API

A private FastAPI service secured with **JWT bearer tokens** (PyJWT) and a
**permission-based Role Based Access Control** system, backed by **SQLite**.

Every endpoint is private: by default no route other than `/health` and the OpenAPI
docs can be reached without a valid access token. Authentication and authorization
can each be switched off from `.env` for local development — see
[Security switches](#security-switches).

## Highlights

- **JWT authentication** with PyJWT — access token expires in **5 minutes**, paired
  with a longer-lived refresh token signed by a *separate* secret.
- **Refresh token rotation** — a refresh token is single use; using it revokes it.
- **Revocation registry** — logout records the token `jti`, so a stolen refresh
  token stops working immediately.
- **Stale-claim protection** — if a user's role changes, tokens issued under the
  old role are rejected with `401` instead of granting outdated privileges.
- **Full HTTP method coverage** — `GET`, `POST`, `PUT`, `PATCH`, `DELETE`, `HEAD`
  and `OPTIONS`, each mapped to a permission.
- **5 roles** with a fixed permission set, plus a rank hierarchy that blocks
  privilege escalation between peers.
- **bcrypt** password hashing, centralised logging, and a project-wide exception
  hierarchy rendered as consistent JSON error envelopes.

## Role matrix

| Role | `read` | `write` | `update` | `delete` | `user:register` | `role:manage` |
|------|:------:|:-------:|:--------:|:--------:|:---------------:|:-------------:|
| `superadmin` | yes | yes | yes | yes | **yes** | yes |
| `admin`      | yes | yes | yes | yes | no  | yes |
| `manager`    | yes | yes | yes | no  | no  | no  |
| `supervisor` | yes | yes | no  | no  | no  | no  |
| `visitor`    | yes | no  | no  | no  | no  | no  |

`admin` has full access **except registering new users** — that is reserved for
`superadmin`, exactly as required.

Rank order (used to prevent peers from modifying each other):
`superadmin` > `admin` > `manager` > `supervisor` > `visitor`.

## Security switches

Authentication and authorization can each be turned off for local development.
**Both default to `true`** — the API is fully secured unless you explicitly opt out.

```dotenv
AUTHENTICATION_ENABLED=true    # false -> no bearer token required
AUTHORIZATION_ENABLED=true     # false -> every RBAC permission check passes
AUTH_BYPASS_USERNAME=superadmin
```

| `AUTHENTICATION_ENABLED` | `AUTHORIZATION_ENABLED` | Behaviour |
|:---:|:---:|---|
| `true` | `true` | **Default.** Token required, RBAC enforced. |
| `false` | `true` | No token needed; every request is served as `AUTH_BYPASS_USERNAME`, whose role still decides access. |
| `true` | `false` | Token still required and validated, but every role may do everything. |
| `false` | `false` | Fully open. |

Disabling either one logs `CRITICAL` at startup, logs a `WARNING` on every affected
request, and is reported by `GET /health`:

```json
{ "status": "ok", "authentication": "disabled", "authorization": "enabled" }
```

Both are development aids. Leave them enabled in any shared or production environment.

## Quick start

```bash
python -m venv venv
venv\Scripts\activate                 # PowerShell: .\venv\Scripts\Activate.ps1
pip install -r requirements.txt
copy .env.example .env                # then fill in the secrets
python run.py
```

Open <http://127.0.0.1:8000/docs>. On first start the bootstrap **superadmin** is
created from `FIRST_SUPERADMIN_*` in `.env` — log in and change that password.

Full instructions, including secret generation, live in
[`.claude/SETUP.md`](.claude/SETUP.md).

## Endpoints

Base prefix: `/api/v1`

### Authentication — `/auth`

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `POST` | `/auth/login` | public | OAuth2 form login → token pair (used by Swagger) |
| `POST` | `/auth/login/json` | public | JSON login → token pair |
| `POST` | `/auth/refresh` | refresh token | Rotate into a new token pair |
| `POST` | `/auth/logout` | bearer | Revoke the presented refresh token |
| `GET` | `/auth/me` | bearer | Current identity + effective permissions |
| `GET` | `/auth/me/permissions` | bearer | Role and permission list only |
| `PATCH` | `/auth/me/password` | bearer | Change your own password |

### Users — `/users`

| Method | Path | Permission | Roles |
|--------|------|------------|-------|
| `POST` | `/users` | `user:register` | superadmin |
| `GET` | `/users` | `read` | all |
| `GET` | `/users/{id}` | `read` | all |
| `HEAD` | `/users/{id}` | `read` | all |
| `PUT` | `/users/{id}` | `update` | superadmin, admin, manager |
| `PATCH` | `/users/{id}` | `update` | superadmin, admin, manager |
| `PATCH` | `/users/{id}/access` | `role:manage` | superadmin, admin |
| `DELETE` | `/users/{id}` | `delete` | superadmin, admin |
| `OPTIONS` | `/users` | any | all (returns a role-aware `Allow` header) |

### Items — `/items`

| Method | Path | Permission | Roles |
|--------|------|------------|-------|
| `GET` | `/items` | `read` | all |
| `GET` | `/items/{id}` | `read` | all |
| `HEAD` | `/items/{id}` | `read` | all |
| `POST` | `/items` | `write` | superadmin, admin, manager, supervisor |
| `PUT` | `/items/{id}` | `update` | superadmin, admin, manager |
| `PATCH` | `/items/{id}` | `update` | superadmin, admin, manager |
| `DELETE` | `/items/{id}` | `delete` | superadmin, admin |
| `OPTIONS` | `/items` | any | all (returns a role-aware `Allow` header) |

### System

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Service and database health (public) |
| `GET` | `/docs`, `/redoc`, `/openapi.json` | API documentation |

## Usage example

```bash
# 1. Log in (5 minute access token)
curl -X POST http://127.0.0.1:8000/api/v1/auth/login \
  -d "username=superadmin&password=<your-password>"

# 2. Call a protected endpoint
curl http://127.0.0.1:8000/api/v1/items \
  -H "Authorization: Bearer <access_token>"

# 3. Register a manager (superadmin only)
curl -X POST http://127.0.0.1:8000/api/v1/users \
  -H "Authorization: Bearer <access_token>" \
  -H "Content-Type: application/json" \
  -d '{"username":"jane","email":"jane@example.com","password":"Passw0rd123","role":"manager"}'

# 4. Rotate the expired access token
curl -X POST http://127.0.0.1:8000/api/v1/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{"refresh_token":"<refresh_token>"}'
```

## Error format

Every failure returns the same envelope:

```json
{
  "error": "AuthorizationError",
  "detail": "Role 'manager' is not allowed to perform this action.",
  "details": { "required": ["delete"], "missing": ["delete"] }
}
```

| Status | Meaning |
|--------|---------|
| `401` | Missing, invalid, expired or revoked token; wrong credentials; deactivated account |
| `403` | Authenticated but the role lacks the required permission |
| `404` | Resource does not exist |
| `409` | Username or e-mail already taken |
| `422` | Payload or business rule validation failure |

## Administration without a token

`POST /api/v1/users` is the registration endpoint (superadmin only), and
`PATCH /api/v1/users/{id}/access` changes a role. When you cannot log in at all —
typically after editing `FIRST_SUPERADMIN_PASSWORD`, which does **not** update an
existing account — use the offline CLI:

```bash
python -m app.cli sync-superadmin      # apply the .env superadmin values
python -m app.cli list-users -v
python -m app.cli create-user --username jane --email jane@example.com --role manager
python -m app.cli set-role --username jane --role admin
python -m app.cli reset-password --username jane
```

Omit `--password` to be prompted, keeping credentials out of your shell history.

## Manual testing

[`API_TEST.md`](API_TEST.md) — every endpoint with its full URL, method and payload,
ready to paste into Postman.

## Verification

```bash
python -m tests.test_rbac_flow          # 89 checks: role matrix, tokens, guards
python -m tests.test_security_switches  # 27 checks: all four switch combinations
```

The first suite logs in as all five roles and asserts every method/role combination
in the matrix above, plus refresh rotation, logout revocation, deactivation,
escalation guards and password rotation. The second runs each
authentication/authorization combination in its own subprocess and asserts the
resulting access.

## Project layout

See [`.claude/ARCHITECTURE.md`](.claude/ARCHITECTURE.md) for a file-by-file map.
