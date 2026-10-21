from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from elements_pulse.config import ConfigError, load_settings
from elements_pulse.timeutil import fmt_ts, parse_ts, time_windows


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for var in (
        "ELEMENTS_CLIENT_ID",
        "ELEMENTS_CLIENT_SECRET",
        "DATABASE_URL",
        "PULSE_CONFIG_FILE",
    ):
        monkeypatch.delenv(var, raising=False)


def test_defaults():
    s = load_settings()
    assert s.api.base_url == "https://api.connect.withsecure.com"
    assert s.collectors.incidents.interval_minutes == 5
    assert s.collectors.security_events.engine_groups == ["epp", "edr"]
    assert not s.has_credentials


def test_yaml_then_env_precedence(tmp_path: Path, monkeypatch):
    cfg = tmp_path / "config.yaml"
    cfg.write_text(
        "collectors:\n  incidents:\n    interval_minutes: 7\n    backfill_days: 3\n"
        "organizations:\n  ids: ['00000000-0000-4000-8000-000000000001']\n"
    )
    monkeypatch.setenv("PULSE_COLLECTORS__INCIDENTS__INTERVAL_MINUTES", "9")
    s = load_settings(cfg)
    assert s.collectors.incidents.interval_minutes == 9  # env wins
    assert s.collectors.incidents.backfill_days == 3  # from YAML
    assert len(s.organizations.ids) == 1


def test_secrets_rejected_in_yaml(tmp_path: Path):
    cfg = tmp_path / "config.yaml"
    cfg.write_text("client_secret: nope\n")
    with pytest.raises(ConfigError, match="must not be set in the YAML"):
        load_settings(cfg)


def test_secret_files(tmp_path: Path, monkeypatch):
    (tmp_path / "id").write_text("demo-id\n")
    (tmp_path / "secret").write_text("demo-secret\n")
    monkeypatch.setenv("ELEMENTS_CLIENT_ID_FILE", str(tmp_path / "id"))
    monkeypatch.setenv("ELEMENTS_CLIENT_SECRET_FILE", str(tmp_path / "secret"))
    s = load_settings()
    assert s.has_credentials
    assert s.client_secret.get_secret_value() == "demo-secret"
    assert "demo-secret" not in repr(s)


def test_csv_env_lists(monkeypatch):
    monkeypatch.setenv("PULSE_COLLECTORS__SECURITY_EVENTS__ENGINE_GROUPS", "epp, ecp")
    monkeypatch.setenv("PULSE_ORGANIZATIONS__IDS", "")
    s = load_settings()
    assert s.collectors.security_events.engine_groups == ["epp", "ecp"]
    assert s.organizations.ids == []


def test_invalid_engine_group(monkeypatch):
    monkeypatch.setenv("PULSE_COLLECTORS__SECURITY_EVENTS__ENGINE_GROUPS", "epp,bogus")
    with pytest.raises(ValueError):
        load_settings()


def test_time_helpers():
    ts = parse_ts("2026-01-15T10:00:02.000Z")
    assert ts == datetime(2026, 1, 15, 10, 0, 2, tzinfo=UTC)
    assert fmt_ts(ts) == "2026-01-15T10:00:02.000Z"
    assert parse_ts("garbage") is None and parse_ts(None) is None
    start = datetime(2026, 1, 1, tzinfo=UTC)
    wins = list(time_windows(start, start + timedelta(days=61), timedelta(days=30)))
    assert len(wins) == 3 and wins[-1][1] == start + timedelta(days=61)
    assert list(time_windows(start, start, timedelta(days=1))) == []
