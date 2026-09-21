"""Regression tests for concise sentinel CLI error reporting."""

import importlib.util
import logging
import sys
from pathlib import Path

_SPEC = importlib.util.spec_from_file_location(
    "gsh_sentinel_deploy_cli_errors",
    Path(__file__).resolve().parent.parent / "scripts" / "gsh-sentinel-deploy.py",
)
_MODULE = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_MODULE)


def _run_main(monkeypatch, *arguments: str) -> int:
    monkeypatch.setattr(
        sys,
        "argv",
        ["gsh-sentinel-deploy", "--target", "test-gateway", *arguments],
    )
    return _MODULE.main()


def test_invalid_yaml_is_one_clean_error_without_traceback(tmp_path, monkeypatch, caplog):
    policy = tmp_path / "invalid.yaml"
    policy.write_text("thresholds: [unterminated", encoding="utf-8")
    caplog.set_level(logging.ERROR, logger="gsh-sentinel")

    result = _run_main(
        monkeypatch,
        "--mode",
        "standard",
        "--policy",
        str(policy),
        "--output",
        str(tmp_path / "output"),
    )

    errors = [record for record in caplog.records if record.levelno >= logging.ERROR]
    assert result == 1
    assert len(errors) == 1
    assert "Invalid YAML" in errors[0].getMessage()
    assert errors[0].exc_info is None


def test_permission_error_is_one_clean_error_without_traceback(tmp_path, monkeypatch, caplog):
    message = f"Output directory '{tmp_path / 'output'}' is not writable"
    runner_calls = []
    monkeypatch.setattr(
        _MODULE.tempfile,
        "NamedTemporaryFile",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(PermissionError("denied")),
    )
    monkeypatch.setattr(
        _MODULE, "run_enforcement_mode", lambda *_args, **_kwargs: runner_calls.append(True)
    )
    caplog.set_level(logging.ERROR, logger="gsh-sentinel")

    result = _run_main(
        monkeypatch,
        "--mode",
        "standard",
        "--output",
        str(tmp_path / "output"),
    )

    errors = [record for record in caplog.records if record.levelno >= logging.ERROR]
    assert result == 1
    assert len(errors) == 1
    assert errors[0].getMessage() == message
    assert errors[0].exc_info is None
    assert runner_calls == []


def test_unexpected_error_retains_traceback(tmp_path, monkeypatch, caplog):
    monkeypatch.setattr(
        _MODULE,
        "run_enforcement_mode",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("unexpected")),
    )
    caplog.set_level(logging.ERROR, logger="gsh-sentinel")

    result = _run_main(
        monkeypatch,
        "--mode",
        "standard",
        "--output",
        str(tmp_path / "output"),
    )

    errors = [record for record in caplog.records if record.levelno >= logging.ERROR]
    assert result == 1
    assert len(errors) == 1
    assert errors[0].getMessage() == "Fatal error"
    assert errors[0].exc_info is not None
