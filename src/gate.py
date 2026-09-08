"""Edge verify-gate: decision logic + memoized verified-state lookup.

Pure decision (`decide_gate`) is separated from IO (`verified_state`) so the
policy can be unit-tested without a database and the endpoint stays thin."""
import time
from dataclasses import dataclass
from enum import Enum
from typing import Optional

from src import db


class GateAction(str, Enum):
    ALLOW = "allow"        # verified + token carries a real email → let the app through
    REFRESH = "refresh"    # verified in DB, but the token still carries <sid>@domain → refresh
    COLLECT = "collect"    # no verified email yet → send to the collection modal


def decide_gate(*, verified: bool, email: str, sid: str, synthetic_domain: str) -> GateAction:
    """Decide what the edge should do for one request.

    `email` is the value oauth2-proxy forwarded as X-Auth-Request-Email. An
    unverified user carries exactly `<sid>@<synthetic_domain>` (ADR-0004); we
    match that string exactly rather than a bare `@<domain>` suffix, because
    `<domain>` (askii.ai) is also a real Moneta email domain."""
    if not verified:
        return GateAction.COLLECT
    if email == f"{sid}@{synthetic_domain}":
        return GateAction.REFRESH
    return GateAction.ALLOW


@dataclass
class _CacheEntry:
    verified: bool
    email: Optional[str]
    expires_at: float


# Bounded on purpose. Entries are added on every miss and removed only by
# evict() on verification, so an unverified population -- exactly the users the
# gate keeps bouncing -- would otherwise accumulate one entry each for the life
# of the container. Sweeping expired entries on insert keeps it proportional to
# active users rather than to every sid ever seen.
_CACHE_MAX_ENTRIES = 10_000
_cache: dict[str, _CacheEntry] = {}


async def verified_state(
    sid: str, ttl_seconds: int, now: Optional[float] = None
) -> tuple[bool, Optional[str]]:
    """Return (verified, real_email) for a synthetic id, memoized for
    `ttl_seconds`. The edge calls this on every request, so a short cache keeps
    the auth path off the database for the common case. `now` is injectable so
    the TTL is testable without wall-clock flakiness."""
    t = time.monotonic() if now is None else now
    entry = _cache.get(sid)
    if entry is not None and entry.expires_at > t:
        return entry.verified, entry.email

    user = await db.fetch_user(sid)
    verified = bool(user and user["verified"])

    if _tombstones.get(sid, -1.0) >= t:
        # Evicted while this lookup was in flight; the answer is already stale.
        return verified, user["real_email"] if user else None
    email = user["real_email"] if user else None

    if len(_cache) >= _CACHE_MAX_ENTRIES:
        for k in [k for k, v in _cache.items() if v.expires_at <= t]:
            del _cache[k]
        for k in [k for k, ts in _tombstones.items() if ts <= t]:
            del _tombstones[k]
        if len(_cache) >= _CACHE_MAX_ENTRIES:
            # Everything is live: drop the entry closest to expiry rather than
            # grow without bound. Losing a memo costs one database read.
            del _cache[min(_cache, key=lambda k: _cache[k].expires_at)]

    _cache[sid] = _CacheEntry(verified=verified, email=email, expires_at=t + ttl_seconds)
    return verified, email


# Set by evict(). verified_state captures the clock before its await and skips
# writing a memo that an evict beat it to -- otherwise a lookup already in
# flight when the user clicks their verification link resumes afterwards and
# re-inserts verified=False with a fresh TTL, which is exactly the stale bounce
# evict exists to prevent. Checking `sid not in _cache` is not enough: the entry
# legitimately is not there yet.
_tombstones: dict[str, float] = {}


def evict(sid: str) -> None:
    """Forget one sid, so the next request re-reads the database.

    Called from /api/verify. Without it a user who clicks their verification
    link and immediately opens an app is still cached as unverified for up to
    the TTL, so the gate bounces them back to /?collect=1 -- where /api/me now
    reports verified, so no modal renders and they see an unexplained bounce."""
    _cache.pop(sid, None)
    _tombstones[sid] = time.monotonic()


def _clear_cache() -> None:
    """Drop every memoized entry and tombstone. Test helper only."""
    _cache.clear()
    _tombstones.clear()
