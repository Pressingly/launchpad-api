"""Edge verify-gate: decision logic + memoized verified-state lookup.

Pure decision (`decide_gate`) is separated from IO (`verified_state`) so the
policy can be unit-tested without a database and the endpoint stays thin."""
from enum import Enum


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
