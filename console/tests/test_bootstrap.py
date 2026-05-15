import pytest

from concrete_console.bootstrap import email_domain


def test_email_domain_lowercases_domain() -> None:
    assert email_domain("Admin@Example.COM") == "example.com"


def test_email_domain_requires_at_sign() -> None:
    with pytest.raises(ValueError):
        email_domain("not-an-email")
