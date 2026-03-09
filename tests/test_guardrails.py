#!/usr/bin/env python3
"""test_guardrails.py — Verify APIOT refuses to run without prerequisites.

Checks:
  1. Missing API key → SystemExit
  2. config.require_openrouter_api_key enforces non-empty key
  3. System prompt contains TASK_ABORTED instruction
  4. System prompt contains isolation rules
  5. Agent event loop handles TASK_ABORTED as a terminal token
  6. lab_bridge aborts on unreachable lab (mocked)
  7. lab_bridge aborts on empty topology (mocked)
"""

import ast
import os
import sys
from pathlib import Path
from unittest.mock import patch

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
APIOT_ROOT = PROJECT_ROOT / "apiot"
sys.path.insert(0, str(PROJECT_ROOT))

PASS = 0
FAIL = 0


def check(label: str, condition: bool, detail: str = ""):
    global PASS, FAIL
    if condition:
        PASS += 1
        print(f"  [PASS] {label}")
    else:
        FAIL += 1
        print(f"  [FAIL] {label}  {detail}")


def test_missing_api_key_aborts():
    print("\n--- config: missing API key raises SystemExit ---")
    with patch.dict(os.environ, {"OPENROUTER_API_KEY": ""}, clear=False):
        try:
            from importlib import reload
            import apiot.core.config as cfg
            reload(cfg)
            cfg.require_openrouter_api_key()
            check("Missing key raises SystemExit", False, "no exception raised")
        except SystemExit as e:
            check("Missing key raises SystemExit", True)
            check("Error message mentions API key", "OPENROUTER_API_KEY" in str(e))
        except Exception as e:
            check("Missing key raises SystemExit", False, f"got {type(e).__name__}: {e}")


def test_valid_api_key_passes():
    print("\n--- config: valid API key passes ---")
    with patch.dict(os.environ, {"OPENROUTER_API_KEY": "sk-or-v1-test"}, clear=False):
        try:
            from importlib import reload
            import apiot.core.config as cfg
            reload(cfg)
            key = cfg.require_openrouter_api_key()
            check("Valid key returns string", isinstance(key, str) and len(key) > 0)
        except Exception as e:
            check("Valid key returns string", False, str(e))


def test_system_prompt_content():
    print("\n--- agent.py: system prompt contains required directives ---")
    from apiot.core.agent import SYSTEM_PROMPT

    check("Prompt mentions TASK_ABORTED", "TASK_ABORTED" in SYSTEM_PROMPT)
    check("Prompt mentions TASK_COMPLETE", "TASK_COMPLETE" in SYSTEM_PROMPT)
    check("Prompt forbids spawn/kill/reset",
          "MUST NOT" in SYSTEM_PROMPT and "spawn" in SYSTEM_PROMPT)
    check("Prompt mentions isolation model", "Isolation model" in SYSTEM_PROMPT)
    check("Prompt mentions read-only lab access", "read-only" in SYSTEM_PROMPT.lower())
    check("Prompt enforces tool-only observations",
          "never fabricate" in SYSTEM_PROMPT.lower())
    check("Prompt requires verify after exploit",
          "verify_crash" in SYSTEM_PROMPT and "verify_shell" in SYSTEM_PROMPT)


def test_terminal_tokens_handled():
    print("\n--- agent.py: TASK_ABORTED is a terminal token ---")
    from apiot.core.agent import TERMINAL_TOKENS

    check("TASK_COMPLETE is terminal", "TASK_COMPLETE" in TERMINAL_TOKENS)
    check("TASK_ABORTED is terminal", "TASK_ABORTED" in TERMINAL_TOKENS)


def test_lab_bridge_aborts_offline():
    print("\n--- lab_bridge: aborts when lab is offline ---")
    with patch("apiot.core.lab_bridge._is_lab_online", return_value=False):
        with patch("apiot.core.lab_bridge.LAB_HEALTH_RETRIES", 0):
            try:
                from apiot.core.lab_bridge import ensure_lab_ready
                ensure_lab_ready()
                check("Offline lab raises SystemExit", False, "no exception")
            except SystemExit:
                check("Offline lab raises SystemExit", True)
            except Exception as e:
                check("Offline lab raises SystemExit", False, f"got {type(e).__name__}")


def test_lab_bridge_aborts_empty_topology():
    print("\n--- lab_bridge: aborts when lab has no devices ---")
    with patch("apiot.core.lab_bridge._is_lab_online", return_value=True):
        mock_client = type("MockClient", (), {
            "get_topology": lambda self: [],
        })()
        with patch("apiot.core.lab_bridge.LabClient", return_value=mock_client):
            try:
                from apiot.core.lab_bridge import ensure_lab_ready
                ensure_lab_ready()
                check("Empty topology raises SystemExit", False, "no exception")
            except SystemExit:
                check("Empty topology raises SystemExit", True)
            except Exception as e:
                check("Empty topology raises SystemExit", False, f"got {type(e).__name__}")


def main():
    test_missing_api_key_aborts()
    test_valid_api_key_passes()
    test_system_prompt_content()
    test_terminal_tokens_handled()
    test_lab_bridge_aborts_offline()
    test_lab_bridge_aborts_empty_topology()

    print(f"\n{'='*50}")
    print(f"Results: {PASS} passed, {FAIL} failed out of {PASS + FAIL}")
    print(f"{'='*50}")
    sys.exit(1 if FAIL else 0)


if __name__ == "__main__":
    main()
