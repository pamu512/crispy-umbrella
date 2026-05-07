"""Tests for typed environment configuration (no real disk or network)."""

from __future__ import annotations

import io
from pathlib import Path

import pytest

from config import CtiAppConfig, SIDEcar_REQUIRED, load_or_exit
from constants import (
    CTI_APP_CONFIG_ENV_KEYS,
    ENV_CTI_DB_PATH,
    ENV_CTI_HTTP_TIMEOUT_SECONDS,
    ENV_CTI_NON_INTERACTIVE,
)
from exceptions import CriticalConfigError


@pytest.fixture
def clean_cti_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for key in CTI_APP_CONFIG_ENV_KEYS:
        monkeypatch.delenv(key, raising=False)


def test_sidecar_required_constant_contains_db_path() -> None:
    assert ENV_CTI_DB_PATH in SIDEcar_REQUIRED


def test_required_missing_raises_critical_config_error(
    clean_cti_env: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv(ENV_CTI_DB_PATH, raising=False)
    with pytest.raises(CriticalConfigError, match="CTI_DB_PATH"):
        CtiAppConfig.from_environ(required=frozenset({ENV_CTI_DB_PATH}))


def test_required_present_loads(
    clean_cti_env: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(ENV_CTI_DB_PATH, "/tmp/vault/cti_vault.db")
    cfg = CtiAppConfig.from_environ(required=SIDEcar_REQUIRED)
    assert cfg.cti_db_path == Path("/tmp/vault/cti_vault.db")


def test_paths_expanduser(
    clean_cti_env: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(ENV_CTI_DB_PATH, "~/data/cti_vault.db")
    cfg = CtiAppConfig.from_environ(required=SIDEcar_REQUIRED)
    assert cfg.cti_db_path is not None
    assert cfg.cti_db_path.name == "cti_vault.db"
    assert cfg.cti_db_path.is_absolute()


def test_bool_env_cast(
    clean_cti_env: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(ENV_CTI_DB_PATH, "/x.db")
    monkeypatch.setenv(ENV_CTI_NON_INTERACTIVE, "YES")
    cfg = CtiAppConfig.from_environ()
    assert cfg.cti_non_interactive is True


def test_bool_invalid_raises(
    clean_cti_env: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(ENV_CTI_DB_PATH, "/x.db")
    monkeypatch.setenv(ENV_CTI_NON_INTERACTIVE, "maybe")
    with pytest.raises(CriticalConfigError, match="Invalid boolean"):
        CtiAppConfig.from_environ()


def test_http_timeout_int(
    clean_cti_env: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(ENV_CTI_DB_PATH, "/x.db")
    monkeypatch.setenv(ENV_CTI_HTTP_TIMEOUT_SECONDS, "120")
    cfg = CtiAppConfig.from_environ()
    assert cfg.http_timeout_seconds == 120


def test_http_timeout_invalid_raises(
    clean_cti_env: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(ENV_CTI_DB_PATH, "/x.db")
    monkeypatch.setenv(ENV_CTI_HTTP_TIMEOUT_SECONDS, "NaN")
    with pytest.raises(CriticalConfigError, match="Invalid integer"):
        CtiAppConfig.from_environ()


def test_load_or_exit_on_missing_required(
    clean_cti_env: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    buf = io.StringIO()
    monkeypatch.delenv(ENV_CTI_DB_PATH, raising=False)
    with pytest.raises(SystemExit) as exc:
        load_or_exit(required=SIDEcar_REQUIRED, stream=buf)
    assert exc.value.code == 1
    err = buf.getvalue()
    assert "CTI_DB_PATH" in err or "missing" in err.lower()
