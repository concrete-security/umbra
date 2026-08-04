from dataclasses import dataclass
import os


@dataclass(frozen=True)
class Settings:
    database_url: str
    raw: dict[str, str]


def load_settings() -> Settings:
    raw = dict(os.environ)
    return Settings(
        database_url=raw.get(
            "DATABASE_URL",
            "postgresql+asyncpg://umbra:umbra@localhost:5432/umbra",
        ),
        raw=raw,
    )


def asyncpg_dsn(database_url: str) -> str:
    return database_url.replace("postgresql+asyncpg://", "postgresql://", 1)
