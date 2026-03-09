#!/usr/bin/env python3
"""test_isolation.py — Verify APIOT cannot control iot_vlab lifecycle.

Checks that:
  - lab_client.py has NO spawn/kill/reset methods
  - lab_bridge.py has NO subprocess calls
  - dispatcher.py has NO spawn/kill/reset routing
  - registry.py tool schemas have NO lifecycle actions
  - No source file under apiot/ references iot_vlab filesystem paths
"""

import ast
import sys
from pathlib import Path

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


def test_lab_client_is_read_only():
    print("\n--- lab_client.py: read-only interface ---")
    src = (APIOT_ROOT / "toolkit" / "lab_client.py").read_text()
    tree = ast.parse(src)

    methods = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name == "LabClient":
            for item in node.body:
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    methods.append(item.name)

    public = [m for m in methods if not m.startswith("_")]
    check("LabClient has get_library", "get_library" in public)
    check("LabClient has get_topology", "get_topology" in public)
    check("LabClient has NO spawn_device", "spawn_device" not in public)
    check("LabClient has NO kill_device", "kill_device" not in public)
    check("LabClient has NO reset_lab", "reset_lab" not in public)


def test_lab_bridge_no_subprocess():
    print("\n--- lab_bridge.py: no subprocess usage ---")
    src = (APIOT_ROOT / "core" / "lab_bridge.py").read_text()
    tree = ast.parse(src)

    imports = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports.add(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                imports.add(node.module)

    check("Does not import subprocess", "subprocess" not in imports)
    check("Does not import os", "os" not in imports)
    check("No Popen calls in source", "Popen" not in src)
    check("No os.system in source", "os.system" not in src)


def test_dispatcher_no_lifecycle():
    print("\n--- dispatcher.py: no lifecycle routing ---")
    src = (APIOT_ROOT / "core" / "tools" / "dispatcher.py").read_text()

    check("No 'spawn' action handler", "spawn_device" not in src)
    check("No 'kill' action handler", "kill_device" not in src)
    check("No 'reset' action handler", "reset_lab" not in src)


def test_registry_no_lifecycle_tools():
    print("\n--- registry.py: no lifecycle tool schemas ---")
    src = (APIOT_ROOT / "core" / "tools" / "registry.py").read_text()

    check("No manage_lab tool", "manage_lab" not in src)
    check("No 'spawn' enum value", '"spawn"' not in src)
    check("No 'kill' enum value", '"kill"' not in src)
    check("No 'reset' enum value", '"reset"' not in src)


def test_no_lifecycle_code():
    print("\n--- Source files: no lifecycle subprocess calls ---")
    lifecycle_patterns = [
        "subprocess.Popen",
        "spawn_device",
        "kill_device",
        "reset_lab",
        "setup_network.sh",
        "lab_manager.py",
    ]
    violations = []

    for py_file in APIOT_ROOT.rglob("*.py"):
        if any(p in ("venv", ".venv", "__pycache__") for p in py_file.parts):
            continue
        if py_file.name == "test_isolation.py":
            continue
        src = py_file.read_text()
        for pattern in lifecycle_patterns:
            if pattern in src:
                rel = py_file.relative_to(APIOT_ROOT)
                violations.append(f"{rel}: contains '{pattern}'")

    check("No source file has lifecycle control code",
          len(violations) == 0,
          "; ".join(violations))


def main():
    test_lab_client_is_read_only()
    test_lab_bridge_no_subprocess()
    test_dispatcher_no_lifecycle()
    test_registry_no_lifecycle_tools()
    test_no_lifecycle_code()

    print(f"\n{'='*50}")
    print(f"Results: {PASS} passed, {FAIL} failed out of {PASS + FAIL}")
    print(f"{'='*50}")
    sys.exit(1 if FAIL else 0)


if __name__ == "__main__":
    main()
