"""Rate limiting for the email-capture endpoints, backed by Valkey.

Design notes that a reader will otherwise have to reconstruct:

*Fixed UTC buckets, not sliding windows.* Keys are bucketed by UTC clock
period — minute ``{yyyy-mm-dd-HH-MM}``, hour ``{yyyy-mm-dd-HH}``, day
``{yyyy-mm-dd}``. A user can therefore spend three submits at 10:59 and three
more at 11:00. That is accepted: it is far simpler than a sliding log and the
threat model does not need the precision. Every key carries a TTL of
bucket-length-remaining plus 60 seconds, so the keyspace self-cleans without
relying on an eviction policy.

*Counting.* Callers invoke :func:`check_and_increment` after validation and
immediately before attempting the send, so a request rejected for a retired
consent version, a malformed address or a missing header does not consume
quota. A send that then fails still counts — the mail was attempted and the
relay saw it.
"""
import logging
import math
from datetime import datetime, timedelta, timezone

import redis.asyncio as redis

from src.config import settings

logger = logging.getLogger(__name__)

# Module-level client. redis.asyncio.from_url() does not open a connection at
# construction time, so building this at import is safe even when Valkey is
# down or absent. The short socket timeouts matter: failing open is worthless
# if every request first hangs for the default timeout waiting to discover it.
#
# Tests simulate an outage by monkeypatching this name, so every code path
# below must dereference the module global at call time rather than capture it.
_client = redis.from_url(
    settings.redis_url,
    socket_connect_timeout=1.0,
    socket_timeout=1.0,
    decode_responses=True,
)

# Scope -> ((short-bucket kind, limit setting), (daily limit setting))
_SCOPES = {
    "submit": ("hour", "rate_limit_submit_per_hour", "rate_limit_submit_per_day"),
    "resend": ("minute", "rate_limit_resend_per_minute", "rate_limit_resend_per_day"),
}


class RateLimitExceeded(Exception):
    """Raised when a scope's limit is exhausted.

    retry_after_seconds: whole seconds until the caller may retry.
    is_global: True when the platform-wide daily ceiling tripped *and* this is
        the first trip of the day-bucket, which the caller must additionally
        audit with a single ``rate_limited`` row (see PRD §4.5). Subsequent
        global trips in the same day-bucket raise with is_global=False so that
        exactly one audit row is written per day; the response the caller
        returns is identical either way. False for per-user limits.
    """

    def __init__(self, retry_after_seconds: int, is_global: bool = False):
        self.retry_after_seconds = retry_after_seconds
        self.is_global = is_global
        super().__init__(
            f"rate limit exceeded (retry after {retry_after_seconds}s, "
            f"global={is_global})"
        )


def _bucket(kind: str, now: datetime) -> tuple[str, int]:
    """Return (bucket label, whole seconds remaining in the bucket) for *now*.

    The label is the key suffix; the remaining seconds drive both the key TTL
    and ``Retry-After``.
    """
    if kind == "minute":
        label = now.strftime("%Y-%m-%d-%H-%M")
        end = now.replace(second=0, microsecond=0) + timedelta(minutes=1)
    elif kind == "hour":
        label = now.strftime("%Y-%m-%d-%H")
        end = now.replace(minute=0, second=0, microsecond=0) + timedelta(hours=1)
    elif kind == "day":
        label = now.strftime("%Y-%m-%d")
        end = now.replace(hour=0, minute=0, second=0, microsecond=0) + timedelta(days=1)
    else:  # pragma: no cover - programming error
        raise ValueError(f"unknown bucket kind: {kind}")
    return label, max(1, math.ceil((end - now).total_seconds()))


async def _incr(key: str, ttl_seconds: int) -> int:
    """Increment *key* and pin its expiry to the end of its bucket plus 60s.

    EXPIRE is re-applied on every hit with the *absolute* remaining lifetime,
    not a fixed bucket length — the latter would push the key's death further
    out with each request and leave stale counters behind the bucket boundary.
    """
    client = _client
    pipe = client.pipeline()
    pipe.incr(key)
    pipe.expire(key, ttl_seconds + 60)
    results = await pipe.execute()
    return int(results[0])


async def _evaluate(
    scope: str, synthetic_id: str, *, consume: bool
) -> tuple[int, bool] | None:
    """Return (retry_after_seconds, is_global) if the caller is over a limit,
    or None if it may proceed.

    With consume=False the counters are read, not incremented -- so a request
    that is about to be rejected for some other reason costs no quota. With
    consume=True they are incremented.

    Every Valkey call the module makes happens inside this coroutine, so the
    caller can wrap exactly this in the fail-open handler.
    """
    short_kind, short_setting, day_setting = _SCOPES[scope]

    now = datetime.now(timezone.utc)

    # Settings are read at call time, not captured at import, so an operator
    # (or a test) can change a limit without reimporting the module.
    short_limit = getattr(settings, short_setting)
    day_limit = getattr(settings, day_setting)
    global_limit = settings.rate_limit_global_per_day

    # Checked tightest-first, and we stop at the first breach. A request
    # rejected by a per-user limit therefore never increments the global
    # counter: a single noisy user must not burn the platform's ceiling.
    async def _count(key: str, ttl: int) -> int:
        """Current usage including this request."""
        if consume:
            return await _incr(key, ttl)
        current = await _client.get(key)
        return int(current or 0) + 1

    short_label, short_ttl = _bucket(short_kind, now)
    if await _count(f"rl:{scope}:{synthetic_id}:{short_label}", short_ttl) > short_limit:
        return short_ttl, False

    day_label, day_ttl = _bucket("day", now)
    if await _count(f"rl:{scope}:{synthetic_id}:{day_label}", day_ttl) > day_limit:
        return day_ttl, False

    if await _count(f"rl:global:{day_label}", day_ttl) > global_limit:
        # Once tripped, the ceiling stays tripped for the rest of the day, so an
        # unconditional ERROR (or audit row) per request is hours of noise that
        # buries the one line an operator needs. SETNX elects the first trip.
        # Only check() elects the first trip, and the asymmetry is load-bearing.
        #
        # The audit row for a global trip is written by the endpoint's 429
        # handler, which is reached only from check(). consume() cannot write it
        # (no database access, by design) and no longer raises. So if consume()
        # were allowed to win this SETNX -- which happens on the overshoot path,
        # when a request that already passed check() pushes the counter over --
        # it would claim the alarm, swallow its own exception, and leave every
        # later check() reporting is_global=False. The once-per-day compliance
        # row would be lost for good and the key burned.
        #
        # check() reads the global counter too (via _count with consume=False),
        # so the very next request still elects correctly. Verified: without
        # this guard an overshooting consume() burns the key and the following
        # check() returns is_global=False.
        first = not consume and await _client.set(
            f"rl:global:{day_label}:alerted", "1", nx=True, ex=day_ttl + 60
        )
        if first:
            logger.error(
                "Platform-wide daily email ceiling of %d reached for %s; "
                "all sends are now refused until the next UTC day.",
                global_limit,
                day_label,
            )
        else:
            logger.warning(
                "Platform-wide daily email ceiling still exhausted for %s.",
                day_label,
            )
        return day_ttl, bool(first)

    return None


async def _guard(scope: str, synthetic_id: str, *, consume: bool) -> None:
    """Shared body of check() / consume(). Raises RateLimitExceeded or returns."""
    # Looked up outside the try: an unknown scope is a programming error, and
    # inside the fail-open handler it would be swallowed and mis-logged as a
    # Valkey outage, sending an operator hunting for a cache problem that never
    # happened while the endpoint silently went unthrottled.
    if scope not in _SCOPES:
        raise ValueError(f"unknown rate limit scope: {scope}")

    try:
        verdict = await _evaluate(scope, synthetic_id, consume=consume)
    except Exception:
        # Fail open. The mpass overlay fails closed because a wrong answer
        # changes who the user is; the limiter fails open because a wrong
        # answer only removes a throttle. Denying every login-adjacent action
        # because a cache is down is a worse outcome than briefly unthrottled
        # email. Do not "fix" this asymmetry — it is deliberate.
        #
        # This covers the increment as well as the check (PRD §4.3): if the
        # increment itself fails, the send proceeds unthrottled.
        logger.error(
            "Rate limiter unavailable for scope=%s; failing open and allowing "
            "the request through.",
            scope,
            exc_info=True,
        )
        return None

    # Raised outside the try so a RateLimitExceeded can never be swallowed by
    # the fail-open handler above.
    if verdict is not None:
        retry_after_seconds, is_global = verdict
        raise RateLimitExceeded(retry_after_seconds, is_global)
    return None


async def check(scope: str, synthetic_id: str) -> None:
    """Would this request be allowed? Increments no counters.

    Raises RateLimitExceeded if the caller is already at a limit, otherwise
    returns. Call this *before* doing the work, so a request that then fails for
    another reason costs no quota.

    Not quite side-effect free, and the exception matters: this is the only
    place that may elect the once-per-day global alarm (the `alerted` key), 
    because it is the only path that can reach the handler which writes the
    audit row. So it is idempotent with respect to quota but not with respect
    to that key -- do not reason about it as a pure read.
    """
    await _guard(scope, synthetic_id, consume=False)


async def consume(scope: str, synthetic_id: str) -> None:
    """Record that a send is about to happen.

    Call this only once the request has actually succeeded and mail is about to
    go out. Quota must track messages sent, not requests received: counting a
    409 or a 400 would let a stale client -- one re-clicking an error it cannot
    resolve -- walk a user, and eventually the whole platform, into the daily
    ceiling and block every genuine verification email for the rest of the day.

    Between check() and consume() a concurrent request can slip through, so a
    bucket may overshoot its limit by one. That is accepted: the alternative is
    holding a lock across a database write and an SMTP send. Do not compensate
    with DECR on failure either -- an expired key would be recreated at -1 with
    no TTL.

    Never raises RateLimitExceeded. This records what happened; it does not get
    to change the outcome. By the time it runs the row is already committed, so
    raising would mean a 500 and no email for a request that had already
    succeeded -- the counter crossing a threshold under a concurrent request is
    exactly the overshoot described above, not a reason to fail the caller.
    """
    try:
        await _guard(scope, synthetic_id, consume=True)
    except RateLimitExceeded:
        logger.info(
            "scope=%s overshot its limit by a concurrent request; the send "
            "proceeds and the next request will be refused.",
            scope,
        )


async def check_and_increment(scope: str, synthetic_id: str) -> None:
    """check() then consume(), for callers that do no fallible work between the
    two.

    Literally both calls, not a consume-only shortcut. Only check() elects the
    once-per-day global alarm (see _evaluate), so a shortcut that merely
    consumed would silently lose the ability to flag a global trip -- which is
    the whole point of calling this instead of consume().

    It does NOT make the pair atomic. They are two round-trips and the counter
    can move between them, so this is convenience for callers that do no
    fallible work in between -- not a substitute for check() ... work ...
    consume() when there is real work to protect.
    """
    await check(scope, synthetic_id)
    await consume(scope, synthetic_id)


async def _reset_for_tests() -> None:
    """Clear the limiter's keyspace.

    SCAN + DEL over the ``rl:*`` prefix rather than FLUSHDB, so a shared
    database is not collateral damage. Deliberately allowed to raise: a test
    fixture that silently failed to reset would produce confusing cross-test
    bleed.

    Call this as *setup* before each test, not only as teardown. pytest-asyncio
    builds a fresh event loop per test, and the module-level client's pooled
    connections are bound to the loop that opened them — reusing one from a
    dead loop raises "Event loop is closed". Dropping the pool here rebinds it
    to the current loop. Without this the error surfaces inside
    check_and_increment, where the fail-open handler swallows it and every
    limit silently stops counting.
    """
    _client.connection_pool.reset()
    keys = [key async for key in _client.scan_iter(match="rl:*", count=500)]
    if keys:
        await _client.delete(*keys)
