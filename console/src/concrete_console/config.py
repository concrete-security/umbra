from dataclasses import dataclass
import os


@dataclass(frozen=True)
class Settings:
    database_url: str


def load_settings() -> Settings:
    return Settings(
        database_url=os.environ.get(
            "DATABASE_URL",
            "postgresql+asyncpg://concrete:concrete@localhost:5432/concrete",
        )
    )


def asyncpg_dsn(database_url: str) -> str:
    return database_url.replace("postgresql+asyncpg://", "postgresql://", 1)
