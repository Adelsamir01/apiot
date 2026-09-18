#!/usr/bin/env python3
"""run_experiment.py — Parameterised single-run experiment driver for APIOT (Computers & Security artifact).

Handles setup, launch, monitoring, teardown, and output collection for one
experiment run. All 42 runs in the paper use this script.

Usage:
    python3 scripts/run_experiment.py \\
        --rq RQ1_RQ2 --protocol coap --topology T1 \\
        --run-id 1 --overseer full --impairment none --session 1 \\
        --output-dir results/RQ1_RQ2/CoAP_T1_run1

See EXT3 spec (artifact/EXPERIMENT_RUNNER.md) for full details.
"""

import argparse
import json
import os
import shutil
import signal
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

# ── Path constants ────────────────────────────────────────────────────
# Standalone APIOT artifact layout:
#   <apiot>/                 ← this repository
#   <apiot>/../iot_vlab/     ← companion IoT Virtual Lab clone (sibling directory)
REPO_ROOT    = Path(__file__).resolve().parent.parent
APIOT_ROOT   = REPO_ROOT
VLAB_ROOT    = Path(os.environ.get("IOT_VLAB_ROOT", str(REPO_ROOT.parent / "iot_vlab")))
IMPAIR_SCRIPT = VLAB_ROOT / "impair_network.sh"
APIOT_DATA   = APIOT_ROOT / "data"
SESSION_LOG_DIR = APIOT_DATA / "logs"

# Impairment profiles (loss_pct, latency_ms, jitter_ms)
IMPAIRMENT_PROFILES = {
    "none":   (0,   0,   0),
    "medium": (5,   50,  10),
    "heavy":  (20,  200, 40),
}

# Topology → number of sim devices to spawn (per protocol)
TOPOLOGY_DEVICE_COUNTS = {
    "T1": 1,  # flat: 1 device
    "T2": 2,  # Purdue: 1 external + 1 internal
    "T3": 3,  # Edge-Fog-Cloud: 3 devices
}


def _git_hash(repo_path: Path) -> str:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=repo_path, capture_output=True, text=True, timeout=5
        )
        return result.stdout.strip() if result.returncode == 0 else "unknown"
    except Exception:
        return "unknown"


def _check_vlab_reachable() -> bool:
    try:
        result = subprocess.run(
            ["curl", "-sf", "--connect-timeout", "5", "http://localhost:5000/topology"],
            capture_output=True, text=True, timeout=10
        )
        return result.returncode == 0
    except Exception:
        return False


def _get_last_session_log() -> Path | None:
    if not SESSION_LOG_DIR.exists():
        return None
    logs = sorted(SESSION_LOG_DIR.glob("session_*.log"), key=lambda p: p.stat().st_mtime)
    return logs[-1] if logs else None


def _apply_impairment(level: str, bridge: str = "br0") -> bool:
    """Apply tc netem impairment. Returns True on success."""
    loss_pct, latency_ms, jitter_ms = IMPAIRMENT_PROFILES[level]
    if loss_pct == 0 and latency_ms == 0:
        return True  # nothing to do

    cmds = []
    if loss_pct > 0:
        cmds.append(["sudo", "bash", str(IMPAIR_SCRIPT), "--loss", str(loss_pct)])
    if latency_ms > 0:
        cmds.append(["sudo", "bash", str(IMPAIR_SCRIPT), "--jitter",
                     str(latency_ms), str(jitter_ms)])

    for cmd in cmds:
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            print(f"[WARN] impair_network.sh failed: {result.stderr.strip()}", flush=True)
            return False
    return True


def _clear_impairment(bridge: str = "br0"):
    subprocess.run(
        ["sudo", "bash", str(IMPAIR_SCRIPT), "--clear"],
        capture_output=True, text=True
    )


def _flush_experiment_iptables():
    """Remove all FORWARD and INPUT rules added by the agent during the experiment.

    We flush the entire FORWARD and INPUT chains to ensure no stale DROP rules
    from a previous run block the next experiment. The lab uses iptables only
    for experiment-level packet filtering — there are no host-critical rules.
    """
    for chain in ("FORWARD", "INPUT"):
        subprocess.run(
            ["sudo", "iptables", "-F", chain],
            capture_output=True, text=True
        )
    print("[INFO] iptables FORWARD and INPUT chains flushed.", flush=True)


def _start_hmi_sim() -> subprocess.Popen | None:
    """Start industrial_hmi_sim.py in the background. Returns the process or None."""
    hmi_script = VLAB_ROOT / "industrial_hmi_sim.py"
    if not hmi_script.exists():
        print("[WARN] industrial_hmi_sim.py not found — skipping HMI background traffic.", flush=True)
        return None
    try:
        proc = subprocess.Popen(
            ["sudo", "python3", str(hmi_script), "--interval", "5"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        print(f"[INFO] HMI simulator started (pid={proc.pid})", flush=True)
        return proc
    except Exception as e:
        print(f"[WARN] Failed to start HMI simulator: {e}", flush=True)
        return None


def _stop_hmi_sim(proc: subprocess.Popen | None):
    if proc is None:
        return
    try:
        proc.terminate()
        proc.wait(timeout=5)
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass


def _start_mqtt_infra(topology: str) -> tuple[object, list[str]]:
    """Spawn QEMU MQTT broker + MQTTClientSim sensor. Returns (manager, [broker_ip]).

    For MQTT, 'manager' is a custom object with stop_all(). The broker is a QEMU
    debian_armel VM with Mosquitto installed. The sensor is MQTTClientSim.
    Blocks until Mosquitto is ready (may take 3-5 minutes for first boot + apt install).
    """
    import requests
    sys.path.insert(0, str(REPO_ROOT))
    from iot_vlab.simulators.sim_manager import SimManager

    LAB_API = "http://127.0.0.1:5000"

    class MQTTInfraManager:
        """Manages QEMU broker + MQTT sensor client lifecycle."""
        def __init__(self):
            self._broker_run_id: str | None = None
            self._sim_mgr = SimManager()
            self._broker_ip: str | None = None

        def setup(self) -> str:
            """Spawn QEMU broker, install Mosquitto, start sensor. Returns broker IP."""
            # 1. Spawn QEMU debian_mqtt_broker
            r = requests.post(f"{LAB_API}/spawn",
                              json={"firmware_id": "debian_mqtt_broker"}, timeout=10)
            if r.status_code != 201:
                raise RuntimeError(f"Failed to spawn debian_mqtt_broker: {r.text[:200]}")
            self._broker_run_id = r.json()["run_id"]
            print(f"[INFO] Spawned debian_mqtt_broker (run_id={self._broker_run_id})", flush=True)

            # 2. Wait for DHCP IP (Linux boots in ~90s)
            print("[INFO] Waiting for QEMU broker DHCP lease (up to 120s)...", flush=True)
            broker_ip = None
            deadline = time.time() + 120
            while time.time() < deadline:
                time.sleep(5)
                try:
                    topo = requests.get(f"{LAB_API}/topology", timeout=5).json()
                    for d in topo:
                        if d.get("id") == self._broker_run_id:
                            ip = d.get("ip")
                            if ip and ip not in ("pending", "unknown"):
                                broker_ip = ip
                                break
                except Exception:
                    pass
                if broker_ip:
                    break
            if not broker_ip:
                raise RuntimeError("MQTT broker never got a DHCP lease")
            self._broker_ip = broker_ip
            print(f"[INFO] MQTT broker IP: {broker_ip}", flush=True)

            # 3. Trigger async Mosquitto install
            r = requests.post(f"{LAB_API}/setup_mqtt/{self._broker_run_id}", timeout=10)
            if r.status_code != 202:
                raise RuntimeError(f"setup_mqtt failed: {r.text[:200]}")
            print("[INFO] Mosquitto setup started (apt install ~2 min)...", flush=True)

            # 4. Poll until ready
            deadline = time.time() + 600
            last_print = 0.0
            while time.time() < deadline:
                time.sleep(5)
                try:
                    state = requests.get(
                        f"{LAB_API}/mqtt_status/{self._broker_run_id}", timeout=5
                    ).json()
                    if time.time() - last_print > 30:
                        print(f"[INFO] Mosquitto status: {state.get('status', '?')}", flush=True)
                        last_print = time.time()
                    if state.get("status") == "ok":
                        break
                    if state.get("status") == "failed":
                        raise RuntimeError(f"Mosquitto setup failed: {state.get('detail')}")
                except Exception as e:
                    if "failed" in str(e):
                        raise
            else:
                raise RuntimeError("Mosquitto setup timed out (600s)")
            print(f"[INFO] Mosquitto ready on {broker_ip}:1883", flush=True)

            # 5. Start MQTTClientSim sensor (connects to QEMU broker)
            self._sim_mgr.start_mqtt_client(
                broker_ip=broker_ip, client_id="iot-sensor-01", publish_interval=5.0
            )
            print(f"[INFO] MQTTClientSim started → {broker_ip}:1883", flush=True)
            return broker_ip

        def stop_all(self):
            # Stop sensor
            if self._broker_ip:
                try:
                    self._sim_mgr.stop_mqtt_client(self._broker_ip)
                except Exception:
                    pass
            # Kill QEMU broker
            if self._broker_run_id:
                try:
                    requests.post(f"{LAB_API}/kill/{self._broker_run_id}", timeout=5)
                except Exception:
                    pass
            print("[INFO] MQTT infrastructure stopped.", flush=True)

    mgr = MQTTInfraManager()
    broker_ip = mgr.setup()
    print(f"[INFO] MQTT broker ready at {broker_ip}:1883", flush=True)
    return mgr, [broker_ip]


def _start_simulators(protocol: str, topology: str) -> tuple[object, list[str]]:
    """Start software simulators and return (manager, [ip, ...])."""
    if protocol == "mqtt":
        return _start_mqtt_infra(topology)

    os.environ["SIM_NO_ALIAS"] = "0"  # use real IP aliases (requires root)
    sys.path.insert(0, str(REPO_ROOT))
    from iot_vlab.simulators.sim_manager import SimManager

    mgr = SimManager()
    ips = []
    n = TOPOLOGY_DEVICE_COUNTS.get(topology, 1)
    for _ in range(n):
        if protocol == "modbus":
            ip = mgr.start_modbus()
        else:
            ip = mgr.start_coap()
        ips.append(ip)
        time.sleep(0.2)  # brief pause between starts

    print(f"[INFO] Started {n} {protocol.upper()} simulator(s): {', '.join(ips)}", flush=True)
    return mgr, ips


def _get_run_stats_from_memory(memory_db: Path) -> dict:
    """Extract final turn count and per-phase stats from memory.db."""
    try:
        import sqlite3
        conn = sqlite3.connect(str(memory_db))
        cur = conn.execute(
            "SELECT MAX(turn_number), COUNT(*), "
            "SUM(CASE WHEN mission_phase='blue' THEN 1 ELSE 0 END) "
            "FROM tool_history"
        )
        row = cur.fetchone()
        total_turns = row[0] or 0
        total_calls = row[1] or 0
        blue_calls  = row[2] or 0

        cur2 = conn.execute(
            "SELECT MIN(turn_number) FROM tool_history WHERE mission_phase='blue'"
        )
        blue_start = (cur2.fetchone() or [None])[0]

        cur3 = conn.execute(
            "SELECT MIN(turn_number) FROM tool_history "
            "WHERE tool_name IN ("
            "'coap_send','modbus_request','tcp_send','udp_send',"
            "'mqtt_publish','mqtt_subscribe',"
            "'execute_exploit','modbus_write_coil',"
            "'modbus_mbap_overflow','coap_option_overflow','brute_force_ssh',"
            "'brute_force_telnet','http_cmd_injection')"
        )
        first_exploit = (cur3.fetchone() or [None])[0]

        cur4 = conn.execute(
            "SELECT vulns_found, patches_applied, devices_tested "
            "FROM sessions ORDER BY start_time DESC LIMIT 1"
        )
        sess = cur4.fetchone()
        conn.close()
        return {
            "total_turns": total_turns,
            "total_tool_calls": total_calls,
            "blue_tool_calls": blue_calls,
            "first_exploit_turn": first_exploit,
            "phase_transition_turn": blue_start,
            "mission_complete_turn": total_turns,
            "vulns_found": sess[0] if sess else 0,
            "patches_applied": sess[1] if sess else 0,
            "devices_tested": sess[2] if sess else 0,
        }
    except Exception as e:
        return {"db_error": str(e)}


def _dry_run(args) -> int:
    """Validate setup without launching the agent. Prints a plan and exits."""
    print("\n[DRY RUN] Validating experiment configuration...")
    print(f"  RQ:         {args.rq}")
    print(f"  Protocol:   {args.protocol}")
    print(f"  Topology:   {args.topology}")
    print(f"  Run ID:     {args.run_id}")
    print(f"  Overseer:   {args.overseer}")
    print(f"  Impairment: {args.impairment}")
    print(f"  Session:    {args.session}")
    print(f"  Output dir: {args.output_dir}")
    print(f"  Timeout:    {args.timeout}s")
    print(f"  Max tokens: {args.max_tokens if args.max_tokens else '(no limit)'}")
    print(f"  Model:      {args.model if args.model else '(from .env LLM_MODEL)'}")
    print(f"  Blind mode: {getattr(args, 'blind', False)}")

    # Check .env / API key
    api_key = os.environ.get("OPENROUTER_API_KEY", "")
    if not api_key:
        env_file = APIOT_ROOT / ".env"
        if env_file.exists():
            for line in env_file.read_text().splitlines():
                if line.startswith("OPENROUTER_API_KEY"):
                    _, _, v = line.partition("=")
                    api_key = v.strip()
    print(f"  API key:    {'SET (' + api_key[:8] + '...)' if api_key else 'MISSING — set OPENROUTER_API_KEY in apiot/.env'}")

    # Check iot_vlab reachable
    vlab_ok = _check_vlab_reachable()
    print(f"  iot_vlab:   {'reachable at localhost:5000' if vlab_ok else 'NOT reachable (start lab_api.py first)'}")

    # Check simulator imports
    try:
        sys.path.insert(0, str(REPO_ROOT))
        from iot_vlab.simulators.sim_manager import SimManager  # noqa
        print("  Simulators: importable ✓")
    except ImportError as e:
        print(f"  Simulators: import failed — {e}")

    # Check impairment script
    imp_ok = IMPAIR_SCRIPT.exists()
    print(f"  impair_network.sh: {'found ✓' if imp_ok else 'MISSING'}")

    # Check git hashes
    print(f"  apiot git:  {_git_hash(APIOT_ROOT)}")
    print(f"  vlab git:   {_git_hash(VLAB_ROOT)}")

    n_devices = TOPOLOGY_DEVICE_COUNTS.get(args.topology, 1)
    profile = IMPAIRMENT_PROFILES[args.impairment]
    print(f"\n[DRY RUN] Would start {n_devices} {args.protocol.upper()} simulator(s)")
    if profile[0] or profile[1]:
        print(f"[DRY RUN] Would apply impairment: loss={profile[0]}% latency={profile[1]}ms jitter={profile[2]}ms")
    if args.impairment == "heavy":
        print("[DRY RUN] Would start industrial_hmi_sim.py (background traffic)")
    overseer_flag = " --no-overseer" if args.overseer == "off" else ""
    print(f"[DRY RUN] Would launch: sudo python3 -m apiot.core.agent --no-tui{overseer_flag}")
    print(f"[DRY RUN] Would write run_result.json to: {args.output_dir}/")
    print("\n[DRY RUN] Validation complete. Run without --dry-run to execute.\n")
    return 0


def run_experiment(args) -> int:
    """Execute one experiment run. Returns exit code (0 = success)."""
    if getattr(args, "dry_run", False):
        return _dry_run(args)
    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    start_ts = datetime.now(timezone.utc)
    start_time = time.time()

    # ── 0. Load .env early so LLM_MODEL is available for run_config ──
    _env_file = APIOT_ROOT / ".env"
    if _env_file.exists():
        for _line in _env_file.read_text().splitlines():
            if "=" in _line and not _line.startswith("#"):
                _k, _, _v = _line.partition("=")
                os.environ.setdefault(_k.strip(), _v.strip())

    # ── 1. Write run config ───────────────────────────────────────────
    run_config = {
        "rq":          args.rq,
        "protocol":    args.protocol,
        "topology":    args.topology,
        "run_id":      args.run_id,
        "overseer":    args.overseer != "off",
        "overseer_mode": args.overseer,
        "impairment":  args.impairment,
        "session":     args.session,
        "memory_db":   args.memory_db,
        "timeout":     args.timeout,
        "git_hash_apiot":   _git_hash(APIOT_ROOT),
        "git_hash_iot_vlab": _git_hash(VLAB_ROOT),
        "timestamp_start": start_ts.isoformat(),
        "model": os.environ.get("LLM_MODEL", "default"),
        "model_override": args.model,
        "blind_mode": getattr(args, "blind", False),
        "status": "running",
    }
    (out_dir / "run_config.json").write_text(json.dumps(run_config, indent=2))
    print(f"[INFO] Run config written to {out_dir}/run_config.json", flush=True)

    # ── 2. Pre-run cleanup ────────────────────────────────────────────
    _flush_experiment_iptables()   # clear any rules left from a previous run
    _clear_impairment()            # clear any leftover tc netem rules

    # ── 2b. Check iot_vlab reachable ──────────────────────────────────
    if not _check_vlab_reachable():
        print("[WARN] iot_vlab REST API not reachable at localhost:5000. "
              "Proceeding with simulator-only topology.", flush=True)

    # ── 3. Prepare memory.db ──────────────────────────────────────────
    target_db = APIOT_DATA / "memory.db"
    APIOT_DATA.mkdir(parents=True, exist_ok=True)

    if args.session == 2 and args.memory_db:
        src_db = Path(args.memory_db)
        if src_db.exists():
            shutil.copy2(src_db, target_db)
            print(f"[INFO] Copied session-1 memory.db from {src_db}", flush=True)
        else:
            print(f"[WARN] --memory-db {src_db} not found; starting fresh.", flush=True)
            target_db.unlink(missing_ok=True)
    else:
        target_db.unlink(missing_ok=True)
        print("[INFO] Starting with fresh memory.db", flush=True)

    # Clear per-session data files so old runs don't bleed into new ones
    for _stale in ["attack_log.json", "remediation_log.json", "network_state.json"]:
        (APIOT_DATA / _stale).unlink(missing_ok=True)
    print("[INFO] Cleared stale attack/remediation/network data.", flush=True)

    # ── 4. Start simulators ───────────────────────────────────────────
    sim_mgr = None
    sim_ips = []
    hmi_proc = None
    try:
        sim_mgr, sim_ips = _start_simulators(args.protocol, args.topology)
    except Exception as e:
        print(f"[WARN] Simulator startup failed: {e}. "
              f"Continuing (may use QEMU devices instead).", flush=True)

    # ── 5. Apply network impairment + optional HMI background traffic ─
    hmi_proc = None
    if args.impairment != "none":
        ok = _apply_impairment(args.impairment)
        if ok:
            profile = IMPAIRMENT_PROFILES[args.impairment]
            print(f"[INFO] Impairment applied: {args.impairment} "
                  f"(loss={profile[0]}%, latency={profile[1]}ms, jitter={profile[2]}ms)",
                  flush=True)
        else:
            print("[WARN] Impairment application failed — running without impairment.",
                  flush=True)
        if args.impairment == "heavy":
            hmi_proc = _start_hmi_sim()

    # ── 6. Launch APIOT ───────────────────────────────────────────────
    env = os.environ.copy()
    # This environment variable controls the optional secondary-LLM path.
    # The agent-level --no-overseer flag disables both it and the guards.
    env["OVERSEER_ENABLED"] = "true" if args.overseer == "full" else "false"
    # Ensure apiot package is importable when launched via sudo -E
    existing_pp = env.get("PYTHONPATH", "")
    repo_root_str = str(REPO_ROOT)
    env["PYTHONPATH"] = f"{repo_root_str}:{existing_pp}" if existing_pp else repo_root_str
    if "OPENROUTER_API_KEY" not in env:
        env_file = APIOT_ROOT / ".env"
        if env_file.exists():
            for line in env_file.read_text().splitlines():
                if "=" in line and not line.startswith("#"):
                    k, _, v = line.partition("=")
                    env.setdefault(k.strip(), v.strip())

    # Model override (for multi-model sensitivity experiments)
    if getattr(args, "model", None):
        env["LLM_MODEL"] = args.model
    # Token budget guard (prevents runaway cost from hallucinating models)
    if getattr(args, "max_tokens", None):
        env["APIOT_MAX_TOKENS"] = str(args.max_tokens)
    else:
        env.pop("APIOT_MAX_TOKENS", None)
    # Blind mode (for model sensitivity experiments — no protocol hints)
    if getattr(args, "blind", False):
        env["APIOT_BLIND_MODE"] = "1"
    else:
        env.pop("APIOT_BLIND_MODE", None)

    agent_cmd = [
        "sudo", "-E", "python3", "-m", "apiot.core.agent",
        "--no-tui",
    ]
    if args.overseer == "off":
        agent_cmd.append("--no-overseer")

    log_path = out_dir / "session.log"
    print(f"[INFO] Launching APIOT: {' '.join(agent_cmd)}", flush=True)
    print(f"[INFO] Log: {log_path}", flush=True)

    outcome = "TIMEOUT"
    process = None
    try:
        with open(log_path, "w") as log_file:
            process = subprocess.Popen(
                agent_cmd,
                stdout=log_file,
                stderr=subprocess.STDOUT,
                env=env,
                cwd=str(REPO_ROOT),
            )

            # ── 7. Monitor for completion ─────────────────────────────
            deadline = time.time() + args.timeout
            poll_interval = 30

            while time.time() < deadline:
                ret = process.poll()
                if ret is not None:
                    # Process exited — check log for terminal token
                    text = log_path.read_text(errors="replace")
                    if "TASK_COMPLETE" in text or "Mission complete. Exiting." in text:
                        outcome = "COMPLETE"
                    elif "TASK_ABORTED" in text or "Mission aborted. Exiting." in text:
                        outcome = "ABORTED"
                    else:
                        outcome = "ERROR"
                    break
                time.sleep(poll_interval)
                elapsed = time.time() - start_time
                print(f"[INFO] Still running... elapsed={elapsed:.0f}s", flush=True)

            if process.poll() is None:
                # Timeout — kill gracefully
                print(f"[WARN] Timeout ({args.timeout}s). Terminating agent.", flush=True)
                process.send_signal(signal.SIGTERM)
                time.sleep(5)
                if process.poll() is None:
                    process.kill()
                outcome = "TIMEOUT"

    except KeyboardInterrupt:
        outcome = "INTERRUPTED"
        if process and process.poll() is None:
            process.terminate()
    finally:
        # ── 8. Teardown ───────────────────────────────────────────────
        if args.impairment != "none":
            _clear_impairment()
            print("[INFO] Network impairment cleared.", flush=True)

        # Always flush iptables rules — agent adds DROP rules during blue phase
        # that must not carry over to the next experiment run.
        _flush_experiment_iptables()

        _stop_hmi_sim(hmi_proc)

        if sim_mgr:
            try:
                sim_mgr.stop_all()
            except Exception as e:
                print(f"[WARN] Simulator teardown error: {e}", flush=True)

    # ── 9. Collect outputs ────────────────────────────────────────────
    end_ts = datetime.now(timezone.utc)
    duration = time.time() - start_time

    for src, dst_name in [
        (APIOT_DATA / "memory.db",           "memory.db"),
        (APIOT_DATA / "attack_log.json",     "attack_log.json"),
        (APIOT_DATA / "network_state.json",  "network_state.json"),
        (APIOT_DATA / "remediation_log.json","remediation_log.json"),
    ]:
        if src.exists():
            shutil.copy2(src, out_dir / dst_name)

    # Copy the most recent session log from apiot/data/logs/
    last_log = _get_last_session_log()
    if last_log and last_log.exists():
        shutil.copy2(last_log, out_dir / "apiot_session.log")

    # ── 10. Write run_result.json ─────────────────────────────────────
    stats = _get_run_stats_from_memory(out_dir / "memory.db") \
        if (out_dir / "memory.db").exists() else {}

    mission_success = outcome == "COMPLETE"

    run_result = {
        "rq":                   args.rq,
        "protocol":             args.protocol,
        "topology":             args.topology,
        "run_id":               args.run_id,
        "overseer":             args.overseer != "off",
        "overseer_mode":        args.overseer,
        "impairment":           args.impairment,
        "impairment_loss_pct":  IMPAIRMENT_PROFILES[args.impairment][0],
        "impairment_latency_ms":IMPAIRMENT_PROFILES[args.impairment][1],
        "impairment_jitter_ms": IMPAIRMENT_PROFILES[args.impairment][2],
        "session":              args.session,
        "outcome":              outcome,
        "mission_success":      mission_success,
        "duration_seconds":     round(duration, 1),
        "git_hash_apiot":       run_config["git_hash_apiot"],
        "git_hash_iot_vlab":    run_config["git_hash_iot_vlab"],
        "model":                run_config["model"],
        "model_override":       args.model,
        "blind_mode":           getattr(args, "blind", False),
        "timestamp_start":      start_ts.isoformat(),
        "timestamp_end":        end_ts.isoformat(),
        "simulator_ips":        sim_ips,
        **stats,
    }
    (out_dir / "run_result.json").write_text(json.dumps(run_result, indent=2))

    # ── 11. Print summary ─────────────────────────────────────────────
    mins, secs = divmod(int(duration), 60)
    turns = stats.get("total_turns", "?")
    print(
        f"\n[DONE] {args.protocol.upper()}/{args.topology}/run{args.run_id} "
        f"overseer={args.overseer} impairment={args.impairment} → "
        f"{outcome} in {turns} turns ({mins}m {secs}s)",
        flush=True,
    )
    return 0 if mission_success else 1


def main():
    parser = argparse.ArgumentParser(
        description="APIOT (Computers & Security artifact) experiment runner — one parameterised run"
    )
    parser.add_argument("--rq",         required=True,
                        choices=["RQ1_RQ2", "RQ3", "RQ4", "RQ6"],
                        help="Research question this run belongs to")
    parser.add_argument("--protocol",   required=True,
                        choices=["coap", "modbus", "mqtt"],
                        help="Target protocol for this run")
    parser.add_argument("--topology",   required=True,
                        choices=["T1", "T2", "T3"],
                        help="Network topology (T1=flat, T2=Purdue, T3=Edge-Fog-Cloud)")
    parser.add_argument("--run-id",     required=True, type=int,
                        help="Replicate number")
    parser.add_argument("--overseer",   required=True,
                        choices=["full", "guards-only", "off", "on"],
                        help="Overseer mode: full (guards + LLM advisory), "
                             "guards-only, or off; 'on' is accepted as a legacy alias for full")
    parser.add_argument("--impairment", default="none",
                        choices=["none", "medium", "heavy"],
                        help="Network impairment level (default: none)")
    parser.add_argument("--session",    default=1, type=int,
                        choices=[1, 2],
                        help="Session number (1=blind, 2=memory-informed for RQ4)")
    parser.add_argument("--memory-db",  default=None,
                        help="Path to session-1 memory.db to copy in for session-2 runs")
    parser.add_argument("--output-dir", required=True,
                        help="Directory to save all run outputs")
    parser.add_argument("--timeout",    default=3600, type=int,
                        help="Max wall-clock time in seconds (default: 3600)")
    parser.add_argument("--dry-run",    action="store_true",
                        help="Validate configuration without launching the agent")
    parser.add_argument("--model",      default=None,
                        help="LLM model to use (overrides LLM_MODEL in .env, "
                             "e.g. anthropic/claude-sonnet-4-6)")
    parser.add_argument("--max-tokens",  default=None, type=int,
                        help="Abort if cumulative LLM tokens exceed this limit "
                             "(sets APIOT_MAX_TOKENS env var; 0 or omit = no limit). "
                             "Recommended for MODEL_SENS runs to prevent runaway cost.")
    parser.add_argument("--blind",      action="store_true",
                        help="Use blind system prompt (no protocol hints) "
                             "for model sensitivity experiments")
    args = parser.parse_args()

    if args.overseer == "on":
        args.overseer = "full"

    sys.exit(run_experiment(args))


if __name__ == "__main__":
    main()
