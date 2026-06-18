"""Tests for startup-time misconfiguration warnings."""


def test_warns_when_smtp_host_is_mailpit(caplog):
    from src.main import _warn_if_dev_smtp_in_prod
    with caplog.at_level("WARNING"):
        _warn_if_dev_smtp_in_prod("mailpit")
    assert any("mailpit" in r.message.lower() for r in caplog.records)
    assert any("staging or production" in r.message.lower() for r in caplog.records)


def test_silent_when_smtp_host_is_real_relay(caplog):
    from src.main import _warn_if_dev_smtp_in_prod
    with caplog.at_level("WARNING"):
        _warn_if_dev_smtp_in_prod("smtp-relay.gmail.com")
    assert not any("mailpit" in r.message.lower() for r in caplog.records)


def test_silent_when_smtp_host_is_empty(caplog):
    """An empty/unset SMTP_HOST is a different misconfig (no SMTP at all).
    The mailpit-specific warning should not fire in that case."""
    from src.main import _warn_if_dev_smtp_in_prod
    with caplog.at_level("WARNING"):
        _warn_if_dev_smtp_in_prod("")
    assert not any("mailpit" in r.message.lower() for r in caplog.records)
