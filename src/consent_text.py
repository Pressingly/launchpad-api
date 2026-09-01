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


def is_valid_version(version: str) -> bool:
    return version in CONSENT_TEXTS


def get_text(version: str) -> str:
    return CONSENT_TEXTS[version]
