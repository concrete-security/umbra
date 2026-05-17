import pytest

from concrete_console.bootstrap import email_domain, write_session_file


def test_email_domain_lowercases_domain() -> None:
    assert email_domain("Admin@Example.COM") == "example.com"


def test_email_domain_requires_at_sign() -> None:
    with pytest.raises(ValueError):
        email_domain("not-an-email")


def test_write_session_file_sets_private_mode(tmp_path) -> None:
    session_path = tmp_path / "nested" / "session.json"

    write_session_file(session_path, {"access_token": "redacted"})

    assert session_path.read_text(encoding="utf-8") == '{\n  "access_token": "redacted"\n}\n'
    assert (session_path.parent.stat().st_mode & 0o777) == 0o700
    assert (session_path.stat().st_mode & 0o777) == 0o600
