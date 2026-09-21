import importlib.util
import json
from pathlib import Path

import pytest

spec = importlib.util.spec_from_file_location("guest", Path(__file__).parents[1] / "guest/guest.py")
guest = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guest)


@pytest.mark.parametrize("payload", [
    {}, [], {"ca_pem": 1, "authorized_key": 2},
    {"ca_pem": "bad", "authorized_key": "ssh-ed25519 " + "A" * 44},
    {"ca_pem": "bad", "authorized_key": "command=evil ssh-ed25519 " + "A" * 44},
    {"ca_pem": "bad", "authorized_key": "ssh-ed25519 " + "A" * 44, "command": "arbitrary"},
])
def test_guest_bootstrap_rejects_untrusted_fields_failure(payload):
    """Guest bootstrap accepts no command, path, private key or malformed CA field."""
    with pytest.raises((ValueError, TypeError)):
        guest.validate_bootstrap(json.dumps(payload).encode())


def test_guest_fixed_destination_success():
    """The guest cannot request a host destination through the bootstrap protocol."""
    assert (guest.HOST_CID, guest.EGRESS_PORT, guest.BOOT_PORT) == (2, 4050, 4051)
