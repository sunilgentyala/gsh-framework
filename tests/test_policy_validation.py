"""
Tests for Sentinel policy schema validation (issue #1).

Every behavioural test runs twice: once through `jsonschema` (skipped if it
is not installed) and once through the stdlib fallback, forced by setting
the script's `jsonschema` module reference to None. Both paths must accept
and reject the same policies with the same messages.
"""

import copy
import importlib.util
import json
import logging
import sys
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_POLICY_PATH = REPO_ROOT / "configs" / "sentinel-policy-default.yaml"
SCHEMA_PATH = REPO_ROOT / "schemas" / "sentinel-policy.schema.json"

_SPEC = importlib.util.spec_from_file_location(
    "gsh_sentinel_deploy_policy_validation",
    REPO_ROOT / "scripts" / "gsh-sentinel-deploy.py",
)
_MODULE = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_MODULE)

_REAL_JSONSCHEMA = _MODULE.jsonschema


@pytest.fixture(params=["jsonschema", "stdlib"])
def backend(request, monkeypatch):
    """Run the test under each validator backend."""
    if request.param == "jsonschema":
        if _REAL_JSONSCHEMA is None:
            pytest.skip("jsonschema is not installed")
        monkeypatch.setattr(_MODULE, "jsonschema", _REAL_JSONSCHEMA)
    else:
        monkeypatch.setattr(_MODULE, "jsonschema", None)
    return request.param


def _default_policy() -> dict:
    return yaml.safe_load(DEFAULT_POLICY_PATH.read_text(encoding="utf-8"))


def _write_policy(tmp_path: Path, policy, name: str = "policy.yaml") -> Path:
    path = tmp_path / name
    path.write_text(yaml.safe_dump(policy), encoding="utf-8")
    return path


def _load_error(path: Path) -> "_MODULE.PolicyValidationError":
    with pytest.raises(_MODULE.PolicyValidationError) as excinfo:
        _MODULE.load_policy(str(path))
    return excinfo.value


# ---------------------------------------------------------------------------
# Valid policies
# ---------------------------------------------------------------------------

def test_default_policy_loads_with_no_warnings(backend, caplog):
    caplog.set_level(logging.WARNING, logger="gsh-sentinel")

    policy = _MODULE.load_policy(str(DEFAULT_POLICY_PATH))

    assert [r for r in caplog.records if r.levelno >= logging.WARNING] == []
    assert policy["hunt_001"]["step_count"]["max_iterations"] == 25
    # Built-in runtime thresholds are still merged in underneath the file.
    assert policy["thresholds"] == _MODULE.DEFAULT_POLICY["thresholds"]


def test_partial_override_policy_is_valid(backend, tmp_path):
    path = _write_policy(tmp_path, {
        "siem_output": "stdout",
        "thresholds": {"tool_calls_per_minute": 10},
        "hunt_001": {"enabled": False},
    })

    policy = _MODULE.load_policy(str(path))

    assert policy["thresholds"]["tool_calls_per_minute"] == 10
    assert policy["thresholds"]["dns_queries_per_minute"] == 50


def test_schema_is_a_valid_draft_2020_12_schema():
    jsonschema = pytest.importorskip("jsonschema")
    jsonschema.Draft202012Validator.check_schema(json.loads(SCHEMA_PATH.read_text("utf-8")))


# ---------------------------------------------------------------------------
# Invalid policies
# ---------------------------------------------------------------------------

def test_missing_required_key_names_field_and_file(backend, tmp_path):
    policy = _default_policy()
    del policy["hunt_001"]["step_count"]["max_iterations"]
    path = _write_policy(tmp_path, policy)

    error = _load_error(path)

    assert str(error) == (
        f"Invalid policy '{path}': "
        "hunt_001.step_count.max_iterations is required but missing"
    )


def test_wrong_type_threshold_names_field_and_file(backend, tmp_path):
    policy = _default_policy()
    policy["hunt_001"]["token_velocity"]["baseline_multiplier"] = "five"
    path = _write_policy(tmp_path, policy)

    error = _load_error(path)

    assert str(error) == (
        f"Invalid policy '{path}': "
        "hunt_001.token_velocity.baseline_multiplier must be a number, got str"
    )


def test_unknown_top_level_section_is_rejected(backend, tmp_path):
    policy = _default_policy()
    policy["telemetry_export"] = {"enabled": True}
    path = _write_policy(tmp_path, policy)

    error = _load_error(path)

    assert str(error) == f"Invalid policy '{path}': unknown top-level section 'telemetry_export'"


def test_typoed_nested_key_suggests_the_real_one(backend, tmp_path):
    policy = _default_policy()
    step_count = policy["hunt_001"]["step_count"]
    step_count["max_iteration"] = step_count.pop("max_iterations")
    path = _write_policy(tmp_path, policy)

    error = _load_error(path)

    assert error.errors == [
        "hunt_001.step_count has unknown key 'max_iteration' (did you mean 'max_iterations'?)",
        "hunt_001.step_count.max_iterations is required but missing",
    ]
    assert str(error).startswith(f"Invalid policy '{path}': 2 errors: ")


@pytest.mark.parametrize(
    ("mutate", "expected"),
    [
        (
            lambda p: p["hunt_001"]["step_count"].update(max_iterations=True),
            "hunt_001.step_count.max_iterations must be an integer, got bool",
        ),
        (
            lambda p: p["hunt_002"]["nxdomain"].update(rate_threshold_percent=140),
            "hunt_002.nxdomain.rate_threshold_percent must be <= 100, got 140",
        ),
        (
            lambda p: p["hunt_003"]["behavioral_drift"].update(drift_threshold_high=-0.1),
            "hunt_003.behavioral_drift.drift_threshold_high must be >= 0, got -0.1",
        ),
        (
            lambda p: p.update(siem_output="carrier-pigeon"),
            "siem_output must be one of: stdout, file, splunk, elastic, windows_eventlog; "
            "got 'carrier-pigeon'",
        ),
        (
            lambda p: p["ztlv"].update(evaluation_order=["capability_manifest", 7]),
            "ztlv.evaluation_order[1] must be a string, got int",
        ),
        (
            lambda p: p.update(thresholds={"dns_queries_per_minute": "lots"}),
            "thresholds.dns_queries_per_minute must be a number, got str",
        ),
        (
            lambda p: p.update(egress_allowlist="api.openai.com"),
            "egress_allowlist must be a list or a mapping, got str",
        ),
    ],
)
def test_specific_error_per_violation(backend, tmp_path, mutate, expected):
    policy = _default_policy()
    mutate(policy)
    path = _write_policy(tmp_path, policy)

    assert _load_error(path).errors == [expected]


@pytest.mark.parametrize(("content", "got"), [("", "null"), ("- a\n- b\n", "list")])
def test_non_mapping_policy_file_is_rejected(backend, tmp_path, content, got):
    path = tmp_path / "policy.yaml"
    path.write_text(content, encoding="utf-8")

    assert _load_error(path).errors == [f"top level must be a mapping, got {got}"]


def test_both_backends_report_identical_errors():
    """The stdlib fallback must not drift from jsonschema on a badly broken policy."""
    if _REAL_JSONSCHEMA is None:
        pytest.skip("jsonschema is not installed")
    schema = json.loads(SCHEMA_PATH.read_text("utf-8"))
    policy = copy.deepcopy(_default_policy())
    policy["bogus"] = 1
    policy["global"]["environment"] = "moon"
    policy["sentinel"] = []
    del policy["hunt_002"]["dns_query_analysis"]["entropy_threshold_bits"]
    policy["hunt_004"]["data_volume"]["read_volume_multiplier"] = None
    policy["ddi_fusion"]["reputation_feeds"]["feeds"][1]["refresh_interval_hours"] = "6"
    policy["actions"] = {"standard": ["log", "page"], "paranoid": ["block"]}

    stdlib_errors = sorted(_MODULE._stdlib_schema_errors(policy, schema))
    library_errors = sorted(_MODULE._jsonschema_errors(policy, schema))

    assert stdlib_errors == library_errors
    assert len(stdlib_errors) == 8


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _run_main(monkeypatch, *arguments: str) -> int:
    monkeypatch.setattr(sys, "argv", ["gsh-sentinel-deploy", *arguments])
    return _MODULE.main()


def test_cli_validate_policy_accepts_default_policy(backend, monkeypatch, capsys):
    result = _run_main(monkeypatch, "--validate-policy", str(DEFAULT_POLICY_PATH))

    assert result == 0
    assert capsys.readouterr().out.strip() == f"OK: policy '{DEFAULT_POLICY_PATH}' is valid"


def test_cli_validate_policy_reports_one_clean_error(backend, tmp_path, monkeypatch, caplog):
    policy = _default_policy()
    policy["hunt_001"]["step_count"]["max_iterations"] = "many"
    path = _write_policy(tmp_path, policy)
    caplog.set_level(logging.ERROR, logger="gsh-sentinel")

    result = _run_main(monkeypatch, "--validate-policy", str(path))

    errors = [record for record in caplog.records if record.levelno >= logging.ERROR]
    assert result == 1
    assert len(errors) == 1
    assert errors[0].getMessage() == (
        f"Invalid policy '{path}': hunt_001.step_count.max_iterations must be an integer, got str"
    )
    assert errors[0].exc_info is None


def test_cli_validate_policy_missing_file_is_an_error(tmp_path, monkeypatch, caplog):
    missing = tmp_path / "nope.yaml"
    caplog.set_level(logging.ERROR, logger="gsh-sentinel")

    result = _run_main(monkeypatch, "--validate-policy", str(missing))

    assert result == 1
    assert f"Policy file not found: '{missing}'" in caplog.text


def test_cli_run_with_invalid_policy_fails_before_starting(backend, tmp_path, monkeypatch, caplog):
    path = _write_policy(tmp_path, {"hunt_001": {"step_count": {"max_iterations": "many"}}})
    runner_calls = []
    monkeypatch.setattr(
        _MODULE, "run_enforcement_mode", lambda *_args, **_kwargs: runner_calls.append(True)
    )
    caplog.set_level(logging.ERROR, logger="gsh-sentinel")

    result = _run_main(
        monkeypatch,
        "--target", "test-gateway",
        "--mode", "standard",
        "--policy", str(path),
        "--output", str(tmp_path / "output"),
    )

    errors = [record for record in caplog.records if record.levelno >= logging.ERROR]
    assert result == 1
    assert runner_calls == []
    assert len(errors) == 1
    assert errors[0].getMessage().startswith(f"Invalid policy '{path}': hunt_001.step_count")
    assert errors[0].exc_info is None


@pytest.mark.parametrize("arguments", [(), ("--target", "gw"), ("--mode", "standard")])
def test_cli_still_requires_target_and_mode_for_a_run(monkeypatch, capsys, arguments):
    with pytest.raises(SystemExit) as excinfo:
        _run_main(monkeypatch, *arguments)

    assert excinfo.value.code == 2
    assert "the following arguments are required" in capsys.readouterr().err
