"""
scripts/_cli_shims.py
Governed Security Hunting (GSH) Framework

Console-script entry points for `pyproject.toml`'s [project.scripts].

The real CLI implementations live in this same directory as standalone,
hyphenated-filename scripts (gsh-sentinel-deploy.py, gsh-mcp-proxy.py, ...)
runnable directly via `python scripts/foo.py`. A hyphen is not valid in a
Python module name, so setuptools entry points can't reference those files
directly - each wrapper here loads its sibling script by file path and
calls its main(), so installing this package (pip install / pipx install)
exposes the same CLIs as normal installed commands (gsh-sentinel-deploy,
gsh-mcp-proxy, ...) without duplicating or restructuring their code.
"""

import importlib.util
import sys
from pathlib import Path

_SCRIPTS_DIR = Path(__file__).resolve().parent


def _run_script(filename: str) -> int:
    spec = importlib.util.spec_from_file_location(Path(filename).stem, _SCRIPTS_DIR / filename)
    if spec is None or spec.loader is None:
        raise ImportError(f"Could not load script '{filename}' from {_SCRIPTS_DIR}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module.main()


def sentinel_deploy() -> None:
    sys.exit(_run_script("gsh-sentinel-deploy.py"))


def mcp_proxy() -> None:
    sys.exit(_run_script("gsh-mcp-proxy.py"))


def probe_eval() -> None:
    sys.exit(_run_script("gsh-probe-eval.py"))


def baseline() -> None:
    sys.exit(_run_script("gsh-baseline.py"))


def ddi_log_parser() -> None:
    sys.exit(_run_script("ddi-log-parser-ai.py"))
