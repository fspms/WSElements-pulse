"""Configuration.

Precedence (highest first): environment variables, optional YAML file, defaults.

Secrets (Elements client credentials, database URL) are accepted ONLY from environment
variables or from files referenced by ``*_FILE`` variables (Docker secrets). Putting them
in the YAML file is rejected on purpose.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Annotated, Any, ClassVar, Literal
from uuid import UUID

import yaml
from pydantic import AliasChoices, BaseModel, Field, SecretStr, field_validator
from pydantic_settings import (
    BaseSettings,
    NoDecode,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
)

from elements_pulse import __version__

# Read-only is a hard rule of this project: this is the only scope ever requested.
READ_SCOPE = "connect.api.read"

ENGINE_GROUPS = ("epp", "edr", "ecp", "xm")

# Keys that must never appear in the YAML file.
_FORBIDDEN_YAML_KEYS = {"client_id", "client_secret", "database_url"}


class ConfigError(ValueError):
    pass


def _csv(value: Any) -> Any:
    """Accept comma-separated strings for list settings coming from environment variables."""
    if isinstance(value, str):
        return [part.strip() for part in value.split(",") if part.strip()]
    return value


class ApiSettings(BaseModel):
    base_url: str = "https://api.connect.withsecure.com"
    timeout_seconds: float = Field(30.0, gt=0)
    request_delay_seconds: float = Field(
        0.25, ge=0, description="Minimum delay between two API requests (all collectors)."
    )
    max_retries: int = Field(5, ge=0, le=20)
    backoff_base_seconds: float = Field(1.0, gt=0)
    backoff_max_seconds: float = Field(60.0, gt=0)
    max_retry_after_seconds: float = Field(300.0, gt=0)
    user_agent: str = f"WSElements-pulse/{__version__} (unofficial community collector)"


class OrganizationsSettings(BaseModel):
    ids: Annotated[list[UUID], NoDecode] = Field(
        default_factory=list,
        description="Organizations to poll. Empty = the default organization of the API client.",
    )
    discover: bool = Field(
        False,
        description=(
            "Poll every company found under the configured organizations (or under the client's "
            "default organization) instead of the configured organizations themselves."
        ),
    )
    discovery_interval_minutes: float = Field(60, ge=5)

    _split_ids = field_validator("ids", mode="before")(lambda v: _csv(v))


class CollectorSettings(BaseModel):
    enabled: bool = True
    interval_minutes: float = Field(10, ge=1)


class IncrementalCollectorSettings(CollectorSettings):
    backfill_days: int = Field(7, ge=1, le=365, description="Initial history window.")
    overlap_minutes: int = Field(
        10, ge=0, le=1440, description="Re-read this much before the cursor to catch late data."
    )


class IncidentsSettings(IncrementalCollectorSettings):
    interval_minutes: float = Field(5, ge=1)
    backfill_days: int = Field(30, ge=1, le=365)


class DetectionsSettings(CollectorSettings):
    interval_minutes: float = Field(5, ge=1)
    max_incidents_per_run: int = Field(
        50, ge=1, le=1000, description="One API call (or more) per incident; caps the cost."
    )


class SecurityEventsSettings(IncrementalCollectorSettings):
    interval_minutes: float = Field(5, ge=1)
    engine_groups: Annotated[list[Literal["epp", "edr", "ecp", "xm"]], NoDecode] = Field(
        default_factory=lambda: ["epp", "edr"]
    )

    _split_engine_groups = field_validator("engine_groups", mode="before")(lambda v: _csv(v))


class DevicesSettings(CollectorSettings):
    interval_minutes: float = Field(15, ge=1)
    states: Annotated[list[Literal["active", "blocked", "inactive"]], NoDecode] = Field(
        default_factory=lambda: ["active", "blocked", "inactive"]
    )

    _split_states = field_validator("states", mode="before")(lambda v: _csv(v))


class AuditLogsSettings(IncrementalCollectorSettings):
    interval_minutes: float = Field(15, ge=1)


class CollectorsSettings(BaseModel):
    incidents: IncidentsSettings = Field(default_factory=IncidentsSettings)
    detections: DetectionsSettings = Field(default_factory=DetectionsSettings)
    security_events: SecurityEventsSettings = Field(default_factory=SecurityEventsSettings)
    devices: DevicesSettings = Field(default_factory=DevicesSettings)
    audit_logs: AuditLogsSettings = Field(default_factory=AuditLogsSettings)


class RetentionSettings(BaseModel):
    api_requests_days: int = Field(14, ge=1)
    collector_runs_days: int = Field(30, ge=1)


class HealthSettings(BaseModel):
    host: str = "0.0.0.0"  # noqa: S104 - inside the container; not published by default
    port: int = Field(8080, ge=1, le=65535)
    stale_after_intervals: float = Field(
        3, gt=0, description="A collector is unhealthy after this many missed intervals."
    )


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="PULSE_",
        env_nested_delimiter="__",
        extra="ignore",
        populate_by_name=True,
    )

    # Secrets: environment only.
    client_id: SecretStr | None = Field(
        None, validation_alias=AliasChoices("ELEMENTS_CLIENT_ID", "PULSE_CLIENT_ID")
    )
    client_secret: SecretStr | None = Field(
        None, validation_alias=AliasChoices("ELEMENTS_CLIENT_SECRET", "PULSE_CLIENT_SECRET")
    )
    database_url: SecretStr = Field(
        SecretStr("postgresql://pulse@localhost:5432/pulse"),
        validation_alias=AliasChoices("DATABASE_URL", "PULSE_DATABASE_URL"),
    )

    log_level: str = "INFO"
    log_format: Literal["json", "console"] = "json"
    auto_migrate: bool = True

    api: ApiSettings = Field(default_factory=ApiSettings)
    organizations: OrganizationsSettings = Field(default_factory=OrganizationsSettings)
    collectors: CollectorsSettings = Field(default_factory=CollectorsSettings)
    retention: RetentionSettings = Field(default_factory=RetentionSettings)
    health: HealthSettings = Field(default_factory=HealthSettings)

    # Set by load_settings() before instantiation.
    _yaml_data: ClassVar[dict[str, Any]] = {}

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        return (
            init_settings,
            env_settings,
            _DictSource(settings_cls, cls._yaml_data),
        )

    @property
    def has_credentials(self) -> bool:
        return bool(
            self.client_id
            and self.client_secret
            and self.client_id.get_secret_value()
            and self.client_secret.get_secret_value()
        )


class _DictSource(PydanticBaseSettingsSource):
    def __init__(self, settings_cls: type[BaseSettings], data: dict[str, Any]):
        super().__init__(settings_cls)
        self._data = data

    def get_field_value(self, field: Any, field_name: str) -> tuple[Any, str, bool]:
        return self._data.get(field_name), field_name, False

    def __call__(self) -> dict[str, Any]:
        return dict(self._data)


def _read_yaml(path: Path) -> dict[str, Any]:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except OSError as exc:
        raise ConfigError(f"Cannot read config file {path}: {exc}") from exc
    except yaml.YAMLError as exc:
        raise ConfigError(f"Invalid YAML in {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise ConfigError(f"Config file {path} must contain a mapping at top level")
    forbidden = _FORBIDDEN_YAML_KEYS & set(data)
    if forbidden:
        raise ConfigError(
            f"{', '.join(sorted(forbidden))} must not be set in the YAML file. "
            "Use environment variables or Docker secrets (*_FILE) instead."
        )
    return data


def _secret_file_overrides(environ: dict[str, str]) -> dict[str, str]:
    """Support Docker secrets: ELEMENTS_CLIENT_SECRET_FILE=/run/secrets/... etc."""
    mapping = {
        "client_id": "ELEMENTS_CLIENT_ID",
        "client_secret": "ELEMENTS_CLIENT_SECRET",
        "database_url": "DATABASE_URL",
    }
    overrides: dict[str, str] = {}
    for field_name, env_name in mapping.items():
        file_var = environ.get(f"{env_name}_FILE")
        if file_var and not environ.get(env_name):
            try:
                overrides[field_name] = Path(file_var).read_text(encoding="utf-8").strip()
            except OSError as exc:
                raise ConfigError(f"Cannot read {env_name}_FILE ({file_var}): {exc}") from exc
    return overrides


def load_settings(config_file: str | Path | None = None) -> Settings:
    path = config_file or os.environ.get("PULSE_CONFIG_FILE")
    Settings._yaml_data = _read_yaml(Path(path)) if path else {}
    overrides = _secret_file_overrides(dict(os.environ))
    return Settings(**overrides)
