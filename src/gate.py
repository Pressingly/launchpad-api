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
    email = user["real_email"] if user else None
    _cache[sid] = _CacheEntry(verified=verified, email=email, expires_at=t + ttl_seconds)
    return verified, email


def evict(sid: str) -> None:
    """Forget one sid, so the next request re-reads the database.

    Called from /api/verify. Without it a user who clicks their verification
    link and immediately opens an app is still cached as unverified for up to
    the TTL, so the gate bounces them back to /?collect=1 -- where /api/me now
    reports verified, so no modal renders and they see an unexplained bounce."""
    _cache.pop(sid, None)


def _clear_cache() -> None:
    """Drop every memoized entry. Test helper only."""
    _cache.clear()
