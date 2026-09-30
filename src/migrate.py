"""Apply sql/schema.sql to the launchpad database.

Run as `python -m src.migrate` with MIGRATE_DATABASE_URL set to a DSN for a
role that owns the launchpad tables (on a fresh database, its owner) or a
superuser; use the same role on every run, since ALTER TABLE needs ownership.
The database and both roles must already exist; creating them is the
deployment's job because it needs a superuser. The whole schema runs in one
transaction, so a refusal leaves the database untouched, and re-running is a
no-op.
"""
import asyncio
import os
import sys
from pathlib import Path

import asyncpg

DSN_ENV = "MIGRATE_DATABASE_URL"
SCHEMA_PATH = Path(__file__).resolve().parent.parent / "sql" / "schema.sql"
REQUIRED_ROLES = ("launchpad_api_user", "mpass_auth_user")


class MigrationRefused(Exception):
    pass


def expected_database() -> str:
    return os.environ.get("DB_NAME", "launchpad")


async def missing_roles(conn: asyncpg.Connection) -> list[str]:
    rows = await conn.fetch(
        "SELECT rolname FROM pg_roles WHERE rolname = ANY($1::text[])",
        list(REQUIRED_ROLES),
    )
    present = {row["rolname"] for row in rows}
    return [role for role in REQUIRED_ROLES if role not in present]


async def refusal_reason(conn: asyncpg.Connection) -> str | None:
    connected_to = await conn.fetchval("SELECT current_database()")
    if connected_to != expected_database():
        return (
            f"connected to database {connected_to!r}, expected {expected_database()!r}. "
            f"Point {DSN_ENV} at the launchpad database."
        )
    absent = await missing_roles(conn)
    if absent:
        return f"missing role(s) {', '.join(absent)}. Create them first; see the README."
    return None


async def apply_schema(dsn: str, schema_sql: str) -> None:
    conn = await asyncpg.connect(dsn)
    try:
        reason = await refusal_reason(conn)
        if reason:
            raise MigrationRefused(reason)
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
    except MigrationRefused as exc:
        print(f"migrate: {exc} No schema change was made.", file=sys.stderr)
        return 1
    except asyncpg.PostgresError as exc:
        print(f"migrate: {exc}", file=sys.stderr)
        return 1
    except (OSError, ValueError, asyncpg.InterfaceError) as exc:
        print(f"migrate: cannot connect ({type(exc).__name__}).", file=sys.stderr)
        return 1
    print("migrate: launchpad schema is up to date.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
