import hashlib

from umbra_security_cvm.binding import BootBinding


def test_boot_binding_canonicalizes_runtime_values_without_plaintext_tokens() -> None:
    binding = BootBinding.from_plaintexts(
        console_url="https://console.example.com",
        entity_id="00000000-0000-4000-8000-000000000001",
        sc_id="00000000-0000-4000-8000-000000000002",
        ingest_token="ingest-plaintext",
        ca_export_token="ca-export-plaintext",
    )

    canonical = binding.canonical_json()
    assert canonical == (
        '{"CONSOLE_URL":"https://console.example.com",'
        '"ca_export_token_sha256":"'
        + hashlib.sha256(b"ca-export-plaintext").hexdigest()
        + '","entity_id":"00000000-0000-4000-8000-000000000001",'
        '"ingest_token_sha256":"'
        + hashlib.sha256(b"ingest-plaintext").hexdigest()
        + '","sc_id":"00000000-0000-4000-8000-000000000002"}'
    )
    assert "ingest-plaintext" not in canonical
    assert "ca-export-plaintext" not in canonical
    assert binding.rtmr3_digest() == hashlib.sha384(canonical.encode("utf-8")).hexdigest()
