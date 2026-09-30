# launchpad-api

Email verification for the FOSS platform. Users signed in through mPass arrive
with a synthetic address (`<mPass id>@<SYNTHETIC_EMAIL_DOMAIN>`); launchpad-api
collects and verifies their real one, and its `verify-gate` ForwardAuth keeps
them out of the apps until that is done. mpass-auth-proxy then serves the
verified address in place of the synthetic one.

FastAPI + uvicorn, PostgreSQL for state, Valkey/Redis for rate limiting, SMTP for
the verification email.

> This service used to live at `launchpad-api/` inside
> [Pressingly/foss-server-bundle](https://github.com/Pressingly/foss-server-bundle).
> That copy is deprecated. This repository is the source of truth for all new
> development, and its history carries the service's commits from the bundle.

## Endpoints

| Path | Auth in front | Purpose |
|---|---|---|
| `GET /api/health` | none | Liveness and readiness |
| `GET /api/verify` | none | Target of the emailed link; the token is the credential |
| `GET /api/authz` | Traefik ForwardAuth | `verify-gate` target for every app router; also reachable under the mpass-auth `/api/*` router |
| `GET /api/me` | mpass-auth | The portal's verification state for the caller |
| `POST /api/email` | mpass-auth | Submit an address to verify |
| `POST /api/email/resend` | mpass-auth | Resend the verification email |
| `POST /api/dismiss` | mpass-auth | Retired, always 410 |

### Routing: cross-repo invariant

Routes are defined here, but the routers live in each deployment (Traefik labels
for compose and Ansible, HTTPRoutes for Kubernetes). Adding, renaming or removing
a route needs a matching change there. On the portal host the bundle uses:

- `/api/*` at priority 20, behind `mpass-auth`
- `/api/verify` and `/api/health` at priority 30, with no auth
- the landing page's catch-all at priority 5, so it never shadows `/api/*`
- the `verify-gate` middleware as a ForwardAuth to `http://<launchpad-api>:8000/api/authz`,
  appended to each app router when the gate is enabled

## Configuration

Every setting is an environment variable. [.env.example](.env.example) is the
full contract with defaults. The ones a deployment must set:

- `DB_PASSWORD`: the `launchpad_api_user` password.
- `SYNTHETIC_EMAIL_DOMAIN`: must equal the value mpass-auth-proxy uses (the
  bundle derives both from `DEFAULT_EMAIL_DOMAIN`). A mismatch silently waves
  verified users through on their synthetic address.
- `PLATFORM_PROTOCOL`, `PLATFORM_DOMAIN`: the portal host the verification link
  points at.
- `SMTP_*`, `FROM_ADDRESS`, `FROM_NAME`: the mail relay.
- `REDIS_URL`: the rate limiter's store (the bundle uses Valkey DB 11).
- `LAUNCHPAD_RELINK_RUNNER`: `manual` or `runner` wherever users already hold app
  accounts under their synthetic address. The ops override CLI refuses while it
  is empty.

## Database

Two steps, in this order, on every deploy. Both are idempotent.

1. **Bootstrap (superuser, owned by the deployment).** Creates the `launchpad`
   database and the LOGIN roles `launchpad_api_user` (read+write) and
   `mpass_auth_user` (read-only on three columns, for mpass-auth-proxy), and
   resets both passwords. It refuses empty passwords, because Postgres accepts
   `PASSWORD ''` silently and that would take every login down.

   ```bash
   LAUNCHPAD_DB_PASSWORD=... LAUNCHPAD_MPASS_DB_PASSWORD=... \
     psql "postgresql://postgres:<pw>@<host>:5432/postgres" -f sql/bootstrap.sql
   ```

   The DSN must name the maintenance database (`postgres`), since `launchpad`
   does not exist on the first run. Needs psql 15 or later (`\getenv`).

   Where the platform manages roles itself (for example CloudNativePG managed
   roles), create the same database, roles and `CONNECT` grant there instead.

2. **Schema (from the image).** Applies [sql/schema.sql](sql/schema.sql) in one
   transaction: tables, constraints, indexes and grants, including upgrades of
   older databases. It refuses, without changing anything, when existing rows
   would violate a constraint, when connected to a database other than
   `DB_NAME` (default `launchpad`), or when either role is missing. Concurrent
   runs wait on an advisory lock, and a run gives up after 10 seconds waiting
   for a table lock rather than stall logins.

   ```bash
   docker run --rm -e MIGRATE_DATABASE_URL=postgresql://<role>:<pw>@<host>:5432/launchpad \
     <image> python -m src.migrate
   ```

   `MIGRATE_DATABASE_URL` is read only by this command, never by the service.
   The role must own the launchpad tables (on a fresh database, the database
   owner) or be a superuser, and should be the same role on every run:
   `ALTER TABLE` needs ownership. Databases built by foss-server-bundle have
   tables owned by `postgres`.

   In Kubernetes this is a Job or an init container running the same image
   with `command: ["python", "-m", "src.migrate"]`.

## Running locally

```bash
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt -r requirements-test.txt
cp .env.example .env   # then fill in the values
uvicorn src.main:app --reload --port 8000
```

## Tests

The suite needs PostgreSQL, Mailpit and Valkey, reachable as `postgres`,
`mailpit` and `valkey`. CI ([.github/workflows/tests.yml](.github/workflows/tests.yml))
builds the schema exactly as a deployment does, bootstrap then migrate, and
runs `python -m pytest`. `TEST_ADMIN_DSN` points the schema and grant tests at a
superuser connection.

## Docker

```bash
docker build -t launchpad-api .
docker run --rm -p 8000:8000 --env-file .env launchpad-api
```

The container listens on port `8000`, runs as a non-root user, and writes no
access log, because `/api/verify` carries the raw token in its query string.

## Operations

`src/ops_override.py` lets an operator set a user's address and complete their
relink on their own authority. Run it inside the container:

```bash
docker exec -it launchpad-api python -m src.ops_override --help
```

## Releases

The intended pipeline follows the other FOSS services: tags trigger Cloud Build,
`vX.Y.Z-rc.N` publishes to the sandbox Artifact Registry, and `vX.Y.Z` publishes
to production after approval. The image path is
`<registry>/foss-launchpad-api/launchpad-api`. The triggers for this repository
are being set up by DevOps and are not live yet.

## License

GPL-3.0. See [LICENSE](LICENSE).
