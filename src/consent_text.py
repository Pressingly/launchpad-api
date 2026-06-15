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
}


def is_valid_version(version: str) -> bool:
    return version in CONSENT_TEXTS


def get_text(version: str) -> str:
    return CONSENT_TEXTS[version]
