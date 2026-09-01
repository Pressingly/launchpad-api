"""Versioned consent text shown to users at the modal.

Each version is preserved here so old audit rows can be re-rendered.
"""

CONSENT_TEXTS = {
    "v1.0": (
        "By providing your email, you agree that FOSS (operated by Moneta) "
        "may send notifications, invites, and other transactional emails "
        "related to your use of the FOSS apps (Outline, Penpot, Plane, "
        "SurfSense, Twenty). Your email is stored within Moneta's "
        "infrastructure and is not shared with third parties. "
        "You can stop notifications by contacting your administrator."
    ),
    # v1.1 — app list corrected. SurfSense was removed from the bundle and
    # Zammad added; v1.0 named the first and omitted the second, so every row
    # written under it records consent for an app that does not exist and no
    # consent for one that does. v1.0 is left byte-for-byte intact: it is stored
    # verbatim in foss_users_audit.consent_text_content and existing rows must
    # keep rendering exactly what their user was shown.
    "v1.1": (
        "By providing your email, you agree that FOSS (operated by Moneta) "
        "may send notifications, invites, and other transactional emails "
        "related to your use of the FOSS apps (Outline, Penpot, Plane, "
        "Twenty, Zammad). Your email is stored within Moneta's "
        "infrastructure and is not shared with third parties. "
        "You can stop notifications by contacting your administrator."
    ),
}


# The version new submissions must carry. CONSENT_TEXTS deliberately keeps every
# older entry so historical foss_users_audit rows still render exactly what their
# user was shown -- but an old version must not be *accepted* going forward, or a
# stale client (a cached index.html, an out-of-date inlined copy, a direct API
# caller) keeps writing consent records for an app roster that no longer matches
# the platform. The server decides the current version, not the caller.
CURRENT_VERSION = "v1.1"


def is_valid_version(version: str) -> bool:
    """True only for the version new submissions must carry.

    Not "is this a version we know about" -- see CURRENT_VERSION."""
    return version == CURRENT_VERSION


def is_known_version(version: str) -> bool:
    """True for any version ever published, including retired ones. Use this to
    render a historical audit row, never to validate an incoming submission."""
    return version in CONSENT_TEXTS


def get_text(version: str) -> str:
    return CONSENT_TEXTS[version]
