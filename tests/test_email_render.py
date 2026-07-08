"""Security: the HTML verification email must escape user-provided values
(display_name) so markup can't be injected; the plain-text template must not escape."""
from src.email_sender import _render

_URL = "https://foss.local.dev/api/verify?token=abc&x=y"


def test_html_template_escapes_display_name():
    out = _render("verify_email.html", display_name="<script>alert(1)</script>",
                  verification_url=_URL, expiry_hours=24)
    assert "<script>" not in out
    assert "&lt;script&gt;" in out


def test_txt_template_is_not_html_escaped():
    out = _render("verify_email.txt", display_name="Ann & Bob",
                  verification_url=_URL, expiry_hours=24)
    assert _URL in out          # & in the URL stays literal (not &amp;)
    assert "&amp;" not in out
