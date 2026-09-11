"""Edge verify-gate: decision logic + memoized verified-state lookup.

Pure decision (`decide_gate`) is separated from IO (`verified_state`) so the
policy can be unit-tested without a database and the endpoint stays thin."""
import time
from dataclasses import dataclass
from enum import Enum
from typing import Optional

from src import db


class GateAction(str, Enum):
    ALLOW = "allow"        # relink complete + token carries a real email → let the app through
    REFRESH = "refresh"    # relink complete, but the token still carries <sid>@domain → refresh
    COLLECT = "collect"    # no email submitted / not verified yet → collection modal
    RELINKING = "relinking"  # verification clicked, relink not done → hold


def is_relink_complete(*, verified: bool, relink_state: str) -> bool:
    """True when the user's app accounts are (or need not be) relinked.

    One helper, because there are two ways to be complete and scattering the
    second one is how it gets missed:

    - `relink_state == 'relinked'` — the ordinary path.
    - `verified` with `relink_state == 'none'` — the LEGACY combination, a user
      who verified before this column existed. There are none in production
      (capture has never been enabled anywhere), but a devstack or test database
      has them, and holding them would lock out test accounts the moment the
      feature was enabled after a test run.

    Deliberately stricter than "relinked OR legacy": `verified` is required in
    both branches. mark_relinked sets both columns in one statement so
    (verified = FALSE, relink_state = 'relinked') is unreachable through the
    code, but if a hand-edited row ever produced it, treating it as complete
    would ALLOW a user whose overlay still serves the synthetic address -- the
    §1 invariant failing one layer above the query that enforces it.
    """
    return verified and relink_state in ("relinked", "none")


def decide_gate(
    *, verified: bool, relink_state: str, email: str, sid: str, synthetic_domain: str
) -> GateAction:
    """Decide what the edge should do for one request.

    `email` is the value oauth2-proxy forwarded as X-Auth-Request-Email. An
    unverified user carries exactly `<sid>@<synthetic_domain>` (ADR-0004); we
    match that string exactly rather than a bare `@<domain>` suffix, because
    `<domain>` (askii.ai) is also a real Moneta email domain.

    pending_relink is checked first and never falls through: that population is
    the one for whom an app visit creates the duplicate account, because their
    relink has not happened yet.

    relink_failed is held the same way, on the same GateAction. A refusal (a
    collision the runner cannot resolve on its own) leaves the user's app
    accounts exactly as unmoved as pending_relink does, so letting them through
    creates the identical duplicate-account bug. Resubmitting from COLLECT would
    only issue another verification link and walk them back into the same
    refusal -- the loop this gate exists to prevent -- so COLLECT is not an
    option either. Distinguishing "still working on it" from "needs an
    administrator" is a message for /api/me and the portal to draw from
    relink_state; the gate only needs to know the user is not through yet, and
    both states agree on that."""
    if relink_state in ("pending_relink", "relink_failed"):
        return GateAction.RELINKING
    if not is_relink_complete(verified=verified, relink_state=relink_state):
        return GateAction.COLLECT
    if email == f"{sid}@{synthetic_domain}":
        return GateAction.REFRESH
    return GateAction.ALLOW


@dataclass
class _CacheEntry:
    verified: bool
    email: Optional[str]
    relink_state: str
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
) -> tuple[bool, Optional[str], str]:
    """Return (verified, real_email, relink_state) for a synthetic id, memoized
    for `ttl_seconds`. The edge calls this on every request, so a short cache
    keeps the auth path off the database for the common case. `now` is
    injectable so the TTL is testable without wall-clock flakiness.

    A row that has never been submitted reports relink_state 'none', which with
    verified False is the "collect" combination -- the same answer the missing
    row itself means."""
    t = time.monotonic() if now is None else now
    entry = _cache.get(sid)
    if entry is not None and entry.expires_at > t:
        return entry.verified, entry.email, entry.relink_state

    user = await db.fetch_user(sid)
    verified = bool(user and user["verified"])
    relink_state = (user or {}).get("relink_state") or "none"

    if _tombstones.get(sid, -1.0) >= t:
        # Evicted while this lookup was in flight; the answer is already stale.
        return verified, (user["real_email"] if user else None), relink_state
    email = user["real_email"] if user else None

    if len(_cache) >= _CACHE_MAX_ENTRIES:
        for k in [k for k, v in _cache.items() if v.expires_at <= t]:
            del _cache[k]
        if len(_cache) >= _CACHE_MAX_ENTRIES:
            # Everything is live: drop the entry closest to expiry rather than
            # grow without bound. Losing a memo costs one database read.
            del _cache[min(_cache, key=lambda k: _cache[k].expires_at)]

    # Sweep tombstones on every write, not inside the cache-size branch. With a
    # 10s TTL the cache only ever holds sids seen in the last 10 seconds, so it
    # never reaches _CACHE_MAX_ENTRIES and a sweep nested under that branch would
    # never run -- leaving one dead float per verification for the life of the
    # container. Older than a full TTL means no in-flight lookup can still need
    # it; `<= t` would discard the tombstone this very call may be racing.
    for k in [k for k, ts in _tombstones.items() if ts < t - ttl_seconds]:
        del _tombstones[k]

    _cache[sid] = _CacheEntry(
        verified=verified,
        email=email,
        relink_state=relink_state,
        expires_at=t + ttl_seconds,
    )
    return verified, email, relink_state


# Set by evict(). verified_state captures the clock before its await and skips
# writing a memo that an evict beat it to -- otherwise a lookup already in
# flight when the user clicks their verification link resumes afterwards and
# re-inserts verified=False with a fresh TTL, which is exactly the stale bounce
# evict exists to prevent. Checking `sid not in _cache` is not enough: the entry
# legitimately is not there yet.
_tombstones: dict[str, float] = {}


def evict(sid: str, now: Optional[float] = None) -> None:
    """Forget one sid, so the next request re-reads the database.

    Called from /api/verify, and required from every other transition too: the
    memo now holds relink_state as well, so a completed relink that does not
    evict leaves the user held at RELINKING for up to the TTL after they are
    entitled to go through. Without it a user who clicks their verification link
    and immediately opens an app is still cached in their previous state for up
    to the TTL, so the gate bounces them somewhere that renders nothing to
    explain why."""
    _cache.pop(sid, None)
    # Same clock base verified_state compares against. `now` is an injectable
    # seam there (the TTL tests pass 100.0), so writing time.monotonic() here
    # unconditionally would leave a tombstone ~8e5 against a test clock of 100
    # -- permanently newer, so every later lookup would early-return and the sid
    # would never be memoized again.
    _tombstones[sid] = time.monotonic() if now is None else now


def _clear_cache() -> None:
    """Drop every memoized entry and tombstone. Test helper only."""
    _cache.clear()
    _tombstones.clear()
