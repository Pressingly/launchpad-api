"""Apply sql/schema.sql to the launchpad database.

Run as `python -m src.migrate` with MIGRATE_DATABASE_URL set to a DSN that may
create tables and grant on them (the database owner or a superuser). The
database and both roles must already exist; creating them is the deployment's
job because it needs a superuser. The whole schema runs in one transaction, so
a refusal leaves the database untouched, and re-running is a no-op.
"""
import asyncio
import os
import sys
from pathlib import Path

import asyncpg

DSN_ENV = "MIGRATE_DATABASE_URL"
SCHEMA_PATH = Path(__file__).resolve().parent.parent / "sql" / "schema.sql"
REQUIRED_ROLES = ("launchpad_api_user", "mpass_auth_user")


class MissingRoles(Exception):
    pass


async def missing_roles(conn: asyncpg.Connection) -> list[str]:
    rows = await conn.fetch(
        "SELECT rolname FROM pg_roles WHERE rolname = ANY($1::text[])",
        list(REQUIRED_ROLES),
    )
    present = {row["rolname"] for row in rows}
    return [role for role in REQUIRED_ROLES if role not in present]


async def apply_schema(dsn: str, schema_sql: str) -> None:
    conn = await asyncpg.connect(dsn)
    try:
        absent = await missing_roles(conn)
        if absent:
            raise MissingRoles(", ".join(absent))
        async with conn.transaction():
            await conn.execute(schema_sql)
    finally:
        await conn.close()


def main() -> int:
    dsn = os.environ.get(DSN_ENV, "")
    if not dsn:
        print(f"migrate: {DSN_ENV} is required.", file=sys.stderr)
        return 2
    try:
        asyncio.run(apply_schema(dsn, SCHEMA_PATH.read_text()))
    except MissingRoles as exc:
        print(
            f"migrate: missing role(s) {exc}. Create the launchpad roles before "
            "migrating; see the README. No schema change was made.",
            file=sys.stderr,
        )
        return 1
    except asyncpg.PostgresError as exc:
        print(f"migrate: {exc}", file=sys.stderr)
        return 1
    print("migrate: launchpad schema is up to date.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
