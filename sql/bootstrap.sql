-- =============================================================================
-- launchpad bootstrap: the database and the two LOGIN roles. Needs a superuser,
-- which is why it is the deployment's step and not the image's. Run it with psql
-- before `python -m src.migrate`, from Ansible, a Kubernetes Job on a postgres
-- image, or by hand:
--
--   LAUNCHPAD_DB_PASSWORD=... LAUNCHPAD_MPASS_DB_PASSWORD=... \
--     psql "$SUPERUSER_DSN" -f sql/bootstrap.sql
--
-- Idempotent: re-running creates what is missing and resets both passwords to
-- the values given, so the cluster is reconciled with the deployment's secrets.
--
-- The empty-password guard has to come BEFORE the first ALTER ROLE:
-- ALTER ROLE ... PASSWORD '' is accepted with only a NOTICE and exits 0 while
-- stripping authentication, and mpass_auth_user being unable to connect means
-- /token returns 503 for every login platform-wide. The post-condition at the
-- end re-checks the outcome as a second line of defence.
-- =============================================================================

\set ON_ERROR_STOP on

-- \getenv leaves a variable UNCHANGED when the environment variable is unset,
-- so pre-set both to empty or the guard below could not see an unset password.
\set db_pw ''
\set mpass_pw ''
\getenv db_pw LAUNCHPAD_DB_PASSWORD
\getenv mpass_pw LAUNCHPAD_MPASS_DB_PASSWORD

SELECT (:'db_pw' = '' OR :'mpass_pw' = '') AS pw_missing \gset
\if :pw_missing
\echo 'REFUSED: LAUNCHPAD_DB_PASSWORD and LAUNCHPAD_MPASS_DB_PASSWORD must both be set and non-empty. Nothing was changed.'
DO $$
BEGIN
    RAISE EXCEPTION 'Refusing to provision: LAUNCHPAD_DB_PASSWORD and LAUNCHPAD_MPASS_DB_PASSWORD must both be set and non-empty. Nothing was changed.';
END
$$;
\endif

-- CREATE DATABASE cannot run in a transaction block and has no IF NOT EXISTS,
-- hence \gexec: the SELECT yields the statement only when the database is absent.
SELECT 'CREATE DATABASE launchpad'
 WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'launchpad')\gexec

DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'launchpad_api_user') THEN
        CREATE ROLE launchpad_api_user WITH LOGIN;
    END IF;
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'mpass_auth_user') THEN
        CREATE ROLE mpass_auth_user WITH LOGIN;
    END IF;
END
$$;

-- WITH LOGIN as well as PASSWORD: a role that pre-existed as NOLOGIN would
-- otherwise keep a password it can never use.
ALTER ROLE launchpad_api_user WITH LOGIN PASSWORD :'db_pw';
ALTER ROLE mpass_auth_user    WITH LOGIN PASSWORD :'mpass_pw';

GRANT CONNECT ON DATABASE launchpad TO launchpad_api_user, mpass_auth_user;

-- Post-condition. Both halves of "can authenticate", because they fail
-- independently: an empty password strips rolpassword, and NOLOGIN blocks a
-- role that has one.
DO $$
DECLARE
    unauthenticated TEXT;
BEGIN
    SELECT string_agg(rolname, ', ')
      INTO unauthenticated
      FROM pg_authid
     WHERE rolname IN ('launchpad_api_user', 'mpass_auth_user')
       AND (rolpassword IS NULL OR NOT rolcanlogin);

    IF unauthenticated IS NOT NULL THEN
        RAISE EXCEPTION
            'Provisioning left % unable to authenticate (no password, or NOLOGIN). Set LAUNCHPAD_DB_PASSWORD and LAUNCHPAD_MPASS_DB_PASSWORD and re-run.',
            unauthenticated;
    END IF;
END
$$;

\echo 'launchpad: database and roles are in place. Next: python -m src.migrate'
