-- =============================================================================
-- launchpad schema -- the single source of truth for what the schema IS and for
-- how any existing database reaches it.
--
-- Applied by `python -m src.migrate` as ONE transaction, so a refusal or error
-- anywhere below leaves the database exactly as it was. Every statement is
-- guarded, so re-running on an up-to-date database is a no-op.
--
-- Prerequisites, owned by the deployment because they need a superuser: the
-- `launchpad` database and the LOGIN roles `launchpad_api_user` and
-- `mpass_auth_user` with non-empty passwords. See the README.
--
-- Two roles connect:
--   launchpad_api_user   read+write on the email-capture tables and read-only
--                        on buzz_identities, used by launchpad-api
--   mpass_auth_user      used by mpass-auth-proxy: read-only on three columns
--                        of foss_users (never verification_token); on
--                        buzz_identities it binds keys, and may only ever set
--                        revoked_at once. See the GRANTs at the bottom.
-- =============================================================================

-- Serialize concurrent runs (several pods starting at once). Without this, two
-- transactions holding the pre-flight's share locks deadlock when each upgrades
-- to the exclusive lock the constraint ALTERs need.
SELECT pg_advisory_xact_lock(hashtext('launchpad-api:schema'));

-- The ALTERs below take an exclusive lock on foss_users, which mpass-auth-proxy
-- reads on every token exchange. Give up quickly rather than queue logins
-- behind a long-running transaction.
SET LOCAL lock_timeout = '10s';

-- -----------------------------------------------------------------------------
-- Pre-flight: everything that can refuse runs before the first mutation, so the
-- message can name the offending values.
-- -----------------------------------------------------------------------------

-- Refuse a relink_state vocabulary that existing rows do not satisfy.
-- Reachable when somebody added the column by hand.
DO $$
DECLARE bad TEXT;
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.columns
                WHERE table_name = 'foss_users' AND column_name = 'relink_state') THEN
        SELECT string_agg(DISTINCT coalesce(relink_state, '<null>'), ', ')
          INTO bad
          FROM foss_users
         WHERE relink_state IS NULL
            OR relink_state NOT IN ('none', 'pending_relink', 'relink_failed', 'relinked');

        IF bad IS NOT NULL THEN
            RAISE EXCEPTION
                'Cannot apply the relink_state constraint: existing rows hold '
                'values outside the vocabulary: %. Decide what each row should '
                'be (none | pending_relink | relink_failed | relinked), UPDATE '
                'them, then re-run. No schema change was made.', bad;
        END IF;
    END IF;
END
$$;

-- Same check on the audit table's action vocabulary.
DO $$
DECLARE bad TEXT;
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.columns
                WHERE table_name = 'foss_users_audit' AND column_name = 'action') THEN
        SELECT string_agg(DISTINCT coalesce(action, '<null>'), ', ')
          INTO bad
          FROM foss_users_audit
         WHERE action IS NULL
            OR action NOT IN ('submit_email', 'verify_email', 'resend_verification',
                              'dismiss_modal', 'submit_email_collision',
                              'rate_limited', 'ops_override', 'relink');

        IF bad IS NOT NULL THEN
            RAISE EXCEPTION
                'Cannot apply the audit action constraint: existing rows hold '
                'values outside the vocabulary: %. foss_users_audit is an '
                'append-only compliance record -- do not delete these rows to '
                'clear the error. Widen the vocabulary in sql/schema.sql '
                'instead. No schema change was made.', bad;
        END IF;
    END IF;
END
$$;

-- Refuse the pre-integrity-hardening index shape.
--
-- `CREATE INDEX IF NOT EXISTS` matches on NAME, not definition, so an older FULL
-- unique idx_foss_users_email would survive the CREATE below. A full-table
-- unique index lets an UNVERIFIED claim on an address permanently block its
-- real owner from registering it, so refusing beats leaving it in place.
-- Rebuilding a unique index on a live table is the operator's call; the
-- conversion is in the integrity-hardening section of foss-server-bundle's
-- dev/docs/launchpad-runbook.md.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_index i
          JOIN pg_class c ON c.oid = i.indexrelid
         WHERE c.relname = 'idx_foss_users_email'
           AND i.indpred IS NULL
    ) THEN
        RAISE EXCEPTION 'idx_foss_users_email exists as a FULL unique index, not the partial (WHERE verified) one this schema expects. This database predates the integrity hardening and needs that migration first -- see the integrity-hardening section of dev/docs/launchpad-runbook.md in foss-server-bundle. Refusing rather than leaving a full index in place, which would let an unverified claim on an address permanently block its real owner. No schema change was made.';
    END IF;
END
$$;

-- -----------------------------------------------------------------------------
-- foss_users: email state per synthetic id.
--
-- Deliberate v1 choices: no BEFORE UPDATE trigger for updated_at (the app sets
-- it), and verification_token / verification_expires are independently
-- nullable (the pair invariant is enforced in the app).
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS foss_users (
    synthetic_id          TEXT        PRIMARY KEY,
    real_email            TEXT        NOT NULL,
    display_name          TEXT,
    verified              BOOLEAN     NOT NULL DEFAULT FALSE,
    verification_token    TEXT,
    verification_expires  TIMESTAMPTZ,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    verified_at           TIMESTAMPTZ,
    relink_state          TEXT        NOT NULL DEFAULT 'none'
        CHECK (relink_state IN ('none', 'pending_relink', 'relink_failed', 'relinked')),
    relink_error          TEXT
);

-- For tables that predate these columns. Existing rows land on 'none', which
-- paired with verified = TRUE is the LEGACY combination the gate reads as
-- relink-complete, so nobody already verified is locked out.
ALTER TABLE foss_users
    ADD COLUMN IF NOT EXISTS relink_state TEXT NOT NULL DEFAULT 'none';
ALTER TABLE foss_users
    ADD COLUMN IF NOT EXISTS relink_error TEXT;

-- Dropped and re-added so the vocabulary can be widened without a bespoke
-- migration. The name matches what the inline CHECK above auto-generates, and
-- src/db.py keys its error handling on it.
ALTER TABLE foss_users
    DROP CONSTRAINT IF EXISTS foss_users_relink_state_check;
ALTER TABLE foss_users
    ADD CONSTRAINT foss_users_relink_state_check
    CHECK (relink_state IN ('none', 'pending_relink', 'relink_failed', 'relinked'));

-- Partial: only a VERIFIED address is exclusive. A full-table unique index would
-- let an unverified claim permanently block the real owner. The duplicate
-- conflict therefore fires on the UPDATE that sets verified = TRUE.
CREATE UNIQUE INDEX IF NOT EXISTS idx_foss_users_email
    ON foss_users(lower(real_email)) WHERE verified;
CREATE INDEX IF NOT EXISTS idx_foss_users_token
    ON foss_users(verification_token) WHERE verification_token IS NOT NULL;

COMMENT ON COLUMN foss_users.relink_state IS
    'How far the app-account relink has got: none | pending_relink | relink_failed | relinked. verified = TRUE with relink_state = ''none'' is the legacy combination (verified before this column existed) and is treated as complete.';

COMMENT ON COLUMN foss_users.verification_token IS
    'sha256(raw verification token) as lowercase hex (64 chars) — NOT the raw token. The raw value exists only in the emailed link and is never persisted, so a dump, backup or leaked read-only credential cannot be replayed to complete someone else''s verification.';

-- -----------------------------------------------------------------------------
-- foss_users_audit: immutable action history. No FK to foss_users so rows
-- outlive the user they describe.
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS foss_users_audit (
    id                    BIGSERIAL   PRIMARY KEY,
    ts                    TIMESTAMPTZ NOT NULL DEFAULT now(),
    synthetic_id          TEXT        NOT NULL,
    action                TEXT        NOT NULL,
    email                 TEXT,
    consent_text_version  TEXT,
    consent_text_content  TEXT,
    ip_address            INET,
    user_agent            TEXT
);

-- Separate from the relink_state constraint on purpose: db.ops_override_write
-- raises AuditVocabularyMissing when it hits a narrower version, keyed on this
-- constraint name. 'dismiss_modal' stays because historical rows reference it.
ALTER TABLE foss_users_audit
    DROP CONSTRAINT IF EXISTS foss_users_audit_action_check;
ALTER TABLE foss_users_audit
    ADD CONSTRAINT foss_users_audit_action_check
    CHECK (action IN ('submit_email', 'verify_email', 'resend_verification',
                      'dismiss_modal', 'submit_email_collision', 'rate_limited',
                      'ops_override', 'relink'));

CREATE INDEX IF NOT EXISTS idx_foss_users_audit_synthetic
    ON foss_users_audit(synthetic_id);
CREATE INDEX IF NOT EXISTS idx_foss_users_audit_ts
    ON foss_users_audit(ts);

-- -----------------------------------------------------------------------------
-- buzz_identities: the Nostr public key mpass-auth-proxy derived for each mPass
-- ID, so a Buzz key stays bound to one person. Only the public half is stored;
-- the secret is re-derived on demand and never persisted. No FK to foss_users:
-- with email capture off a Buzz user has no foss_users row.
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS buzz_identities (
    sub         TEXT        PRIMARY KEY,
    pubkey_hex  TEXT        NOT NULL UNIQUE
        CONSTRAINT buzz_identities_pubkey_hex_check CHECK (pubkey_hex ~ '^[0-9a-f]{64}$'),
    email       TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at  TIMESTAMPTZ
);

COMMENT ON COLUMN buzz_identities.sub IS
    'The mPass ID (Cognito cognito:username, the same value as foss_users.synthetic_id), never the Cognito sub.';

COMMENT ON COLUMN buzz_identities.pubkey_hex IS
    'BIP-340 x-only public key as 64 lowercase hex characters. Unique so one Nostr key can never be bound to two people.';

COMMENT ON COLUMN buzz_identities.revoked_at IS
    'Set when the identity is revoked; mpass-auth-proxy then refuses to issue its key. One-way: once set it cannot be cleared or changed (see buzz_identities_revocation_is_final). Rows are never deleted, so a revoked key cannot be re-bound.';

-- Revocation is final for every role, the table owner included, so a leaked
-- mpass_auth_user credential cannot un-revoke a key with SET revoked_at = NULL.
-- Un-revoking is a deliberate manual superuser operation: disable this trigger
-- (or SET LOCAL session_replication_role = replica) inside the transaction
-- that clears the column.
CREATE OR REPLACE FUNCTION buzz_identities_keep_revocation() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.revoked_at IS NOT NULL AND NEW.revoked_at IS DISTINCT FROM OLD.revoked_at THEN
        RAISE EXCEPTION 'buzz_identities: revocation of % is final; revoked_at cannot be cleared or changed', OLD.sub;
    END IF;
    RETURN NEW;
END
$$;

DROP TRIGGER IF EXISTS buzz_identities_revocation_is_final ON buzz_identities;
CREATE TRIGGER buzz_identities_revocation_is_final
    BEFORE UPDATE ON buzz_identities
    FOR EACH ROW EXECUTE FUNCTION buzz_identities_keep_revocation();

-- -----------------------------------------------------------------------------
-- Grants. No UPDATE or DELETE on the audit table: it is the consent record this
-- feature exists to produce, and a leaked launchpad_api_user credential must not
-- be able to erase it. mpass_auth_user gets a column-level SELECT because its
-- only query is
--   SELECT real_email FROM foss_users WHERE synthetic_id = $1 AND verified = TRUE
-- so it can never read verification tokens, hashed or otherwise.
--
-- On buzz_identities mpass_auth_user binds keys: INSERT names only sub,
-- pubkey_hex and email, so it cannot insert a pre-revoked row or backdate
-- created_at. Its UPDATE (revoked_at) is for the revoke path that lands later
-- in mpass-auth-proxy; the trigger above keeps that update one-way. No DELETE
-- and no UPDATE of pubkey_hex, so a leaked credential cannot move a person onto
-- another key. launchpad-api does not manage Buzz identities and only reads
-- them. The REVOKE first makes the grant set exact on every run, column
-- privileges included.
-- -----------------------------------------------------------------------------
GRANT USAGE ON SCHEMA public TO launchpad_api_user, mpass_auth_user;

GRANT SELECT, INSERT, UPDATE, DELETE ON foss_users        TO launchpad_api_user;
GRANT SELECT, INSERT                 ON foss_users_audit  TO launchpad_api_user;
GRANT USAGE ON SEQUENCE foss_users_audit_id_seq           TO launchpad_api_user;

GRANT SELECT (synthetic_id, real_email, verified) ON foss_users TO mpass_auth_user;

REVOKE ALL ON buzz_identities FROM launchpad_api_user, mpass_auth_user;
GRANT SELECT                         ON buzz_identities   TO launchpad_api_user;
GRANT SELECT                         ON buzz_identities   TO mpass_auth_user;
GRANT INSERT (sub, pubkey_hex, email) ON buzz_identities  TO mpass_auth_user;
GRANT UPDATE (revoked_at)            ON buzz_identities   TO mpass_auth_user;
