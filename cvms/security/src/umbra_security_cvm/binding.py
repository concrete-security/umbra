from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from collections.abc import Mapping
from uuid import UUID


REQUIRED_ENV = (
    "CONSOLE_URL",
    "ENTITY_ID",
    "SC_ID",
    "CONSOLE_INGEST_TOKEN",
    "CA_EXPORT_TOKEN",
)


@dataclass(frozen=True)
class BootBinding:
    console_url: str
    entity_id: str
    sc_id: str
    ingest_token_sha256: str
    ca_export_token_sha256: str

    @classmethod
    def from_plaintexts(
        cls,
        *,
        console_url: str,
        entity_id: str | UUID,
        sc_id: str | UUID,
        ingest_token: str,
        ca_export_token: str,
    ) -> BootBinding:
        if not console_url:
            raise ValueError("CONSOLE_URL is required")
        if not ingest_token:
            raise ValueError("CONSOLE_INGEST_TOKEN is required")
        if not ca_export_token:
            raise ValueError("CA_EXPORT_TOKEN is required")
        return cls(
            console_url=console_url,
            entity_id=str(UUID(str(entity_id))),
            sc_id=str(UUID(str(sc_id))),
            ingest_token_sha256=sha256_hex(ingest_token),
            ca_export_token_sha256=sha256_hex(ca_export_token),
        )

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> BootBinding:
        source = os.environ if env is None else env
        missing = [name for name in REQUIRED_ENV if not source.get(name)]
        if missing:
            raise ValueError(f"missing Security CVM boot env: {', '.join(missing)}")
        return cls.from_plaintexts(
            console_url=source["CONSOLE_URL"],
            entity_id=source["ENTITY_ID"],
            sc_id=source["SC_ID"],
            ingest_token=source["CONSOLE_INGEST_TOKEN"],
            ca_export_token=source["CA_EXPORT_TOKEN"],
        )

    def payload(self) -> dict[str, str]:
        return {
            "CONSOLE_URL": self.console_url,
            "ca_export_token_sha256": self.ca_export_token_sha256,
            "entity_id": self.entity_id,
            "ingest_token_sha256": self.ingest_token_sha256,
            "sc_id": self.sc_id,
        }

    def canonical_json(self) -> str:
        return json.dumps(self.payload(), sort_keys=True, separators=(",", ":"))

    def rtmr3_digest(self) -> str:
        return hashlib.sha384(self.canonical_json().encode("utf-8")).hexdigest()


def sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()
