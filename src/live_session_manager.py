#!/usr/bin/env python3
"""Thread-safe Live Session Manager for CAN-Sentinel.

Orchestrates:
1. Unix Domain Socket server at /tmp/can_sentinel.sock.
2. Launching build/can_sniffer --socket as a subprocess.
3. Stream ingestion of JSON events matching version 1 contract.
4. Incremental 1-second window creation and scoring via original Isolation Forest.
5. Thread-safe snapshot query for polling frontend.
6. Graceful shutdown, CSV capture persistence, and final AnalysisResult production.
"""

import csv
import json
import os
import queue
import signal
import socket
import subprocess
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import joblib

if __package__:
    from .alert_explainer import explain_window
    from .incident_engine import correlate_incidents
else:
    from alert_explainer import explain_window
    from incident_engine import correlate_incidents

if __package__:
    from .api_analysis_service import (
        ApiAnalysisService,
        DEFAULT_MODEL_PATH,
        WINDOW_MS,
        format_frequency_row,
        get_model_info,
    )
    from .frequency_analyzer import (
        EXPECTED_HEADER,
        KNOWN_IDS,
        build_frequency_summary,
        build_window_features,
        ns_to_timestamp,
        timestamp_to_ns,
    )
    from .isolation_forest_detector import FEATURE_COLUMNS
    from .socket_receiver import SOCKET_PATH, remove_stale_socket, validate_event
else:
    from api_analysis_service import (
        ApiAnalysisService,
        DEFAULT_MODEL_PATH,
        WINDOW_MS,
        format_frequency_row,
        get_model_info,
    )
    from frequency_analyzer import (
        EXPECTED_HEADER,
        KNOWN_IDS,
        build_frequency_summary,
        build_window_features,
        ns_to_timestamp,
        timestamp_to_ns,
    )
    from isolation_forest_detector import FEATURE_COLUMNS
    from socket_receiver import SOCKET_PATH, remove_stale_socket, validate_event

ROOT = Path(__file__).resolve().parents[1]
WINDOW_NS = WINDOW_MS * 1_000_000


class LiveSessionManager:
    """Manages active live capture and real-time inference sessions."""

    def __init__(
        self,
        analysis_service: ApiAnalysisService,
        model_path: Optional[Path] = None,
        captures_dir: Optional[Path] = None,
        sniffer_path: Optional[Path] = None,
        attack_path: Optional[Path] = None,
        normal_path: Optional[Path] = None,
        socket_path: str = SOCKET_PATH,
    ):
        self.analysis_service = analysis_service
        self.model_path = model_path or DEFAULT_MODEL_PATH
        self.captures_dir = captures_dir or (ROOT / "data")
        self.captures_dir.mkdir(parents=True, exist_ok=True)
        self.sniffer_path = sniffer_path or (ROOT / "build" / "can_sniffer")
        self.attack_path = attack_path or (ROOT / "build" / "attack_simulator")
        self.normal_path = normal_path or (ROOT / "build" / "normal_traffic")
        self.socket_path = socket_path

        self._lock = threading.RLock()
        self._active_session: Optional[Dict[str, Any]] = None
        self._sniffer_proc: Optional[subprocess.Popen] = None
        self._attack_proc: Optional[subprocess.Popen] = None
        self._normal_proc: Optional[subprocess.Popen] = None
        self._server_sock: Optional[socket.socket] = None
        self._receiver_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._incident_queue = queue.Queue()
        self._incident_handler = None
        self._shutdown_lock = threading.Lock()
        self._shutdown_requested = False
        self._shutdown_complete = False
        self._processed_incident_ids = set()
        self._response_audit_trail: List[Dict[str, Any]] = []
        self._incident_worker = threading.Thread(
            target=self._incident_worker_loop,
            daemon=True,
            name="CANIncidentWorker",
        )
        self._incident_worker.start()

    def set_incident_handler(self, handler) -> None:
        """Set an optional callback for automatic incident response."""
        self._incident_handler = handler
    def start_attack(self, session_id: str, mode: int = 1) -> Dict[str, Any]:
        """Start a backend-owned attack simulator on vcan0."""
        if mode not in (1, 2):
            raise ValueError("Attack mode must be 1 or 2.")

        with self._lock:
            session = self._active_session

            if not session or session["id"] != session_id:
                raise ValueError("Live session not found.")

            if session.get("interface") != "vcan0":
                raise ValueError("Attack generation is restricted to vcan0.")

            if session.get("state") != "capturing":
                raise ValueError("Live capture is not running.")

            if self._attack_proc and self._attack_proc.poll() is None:
                raise RuntimeError("An attack simulator is already running.")

            attack_path = self.attack_path

            if not attack_path.is_file() or not os.access(attack_path, os.X_OK):
                raise FileNotFoundError("Attack simulator binary is unavailable.")

            self._attack_proc = subprocess.Popen(
                [str(attack_path), str(mode)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )

            started_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
            attack_record = {
                "attack_id": f"att_{len(session.setdefault('attack_history', [])) + 1}",
                "mode": mode,
                "pid": self._attack_proc.pid,
                "state": "RUNNING",
                "started_at": started_at,
                "stopped_at": None,
                "return_code": None,
                "termination_reason": None,
            }
            session["attack_history"].append(attack_record)
            session["attack"] = dict(attack_record)

            session["recovery"] = {
                "state": "ATTACK_RUNNING",
                "normal_windows": 0,
                "required_normal_windows": 2,
                "stopped_after_window_index": None,
            }
            return dict(session["attack"])

    def start_normal(self, session_id: str, interval_ms: int = 100) -> Dict[str, Any]:
        """Start a backend-owned normal traffic generator on vcan0."""
        if not (1 <= interval_ms <= 60000):
            raise ValueError("Interval must be between 1 and 60000 ms.")

        with self._lock:
            session = self._active_session

            if not session or session["id"] != session_id:
                raise ValueError("Live session not found.")

            if session.get("interface") != "vcan0":
                raise ValueError("Traffic generation is restricted to vcan0.")

            if session.get("state") != "capturing":
                raise ValueError("Live capture is not running.")

            if self._normal_proc and self._normal_proc.poll() is None:
                raise RuntimeError("A normal traffic generator is already running.")

            normal_path = self.normal_path

            if not normal_path.is_file() or not os.access(normal_path, os.X_OK):
                raise FileNotFoundError("Normal traffic generator binary is unavailable.")

            self._normal_proc = subprocess.Popen(
                [str(normal_path), str(interval_ms)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )

            started_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
            normal_record = {
                "normal_id": f"norm_{len(session.setdefault('normal_history', [])) + 1}",
                "pid": self._normal_proc.pid,
                "state": "RUNNING",
                "started_at": started_at,
                "stopped_at": None,
                "return_code": None,
                "termination_reason": None,
                "interval_ms": interval_ms,
            }
            session["normal_history"].append(normal_record)
            session["normal"] = dict(normal_record)
            return dict(session["normal"])

    def stop_normal(self, session_id: str, reason: str = "MANUAL_USER_STOP") -> Dict[str, Any]:
        """Stop only the normal traffic generator owned by this manager."""
        with self._lock:
            session = self._active_session

            if not session or session["id"] != session_id:
                raise ValueError("Live session not found.")

            proc = self._normal_proc

            if proc is None:
                return {"state": "NOT_RUNNING"}

            if proc.poll() is None:
                proc.send_signal(signal.SIGINT)

                try:
                    proc.wait(timeout=3.0)
                except subprocess.TimeoutExpired:
                    proc.terminate()
                    try:
                        proc.wait(timeout=2.0)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                        try:
                            proc.wait(timeout=2.0)
                        except subprocess.TimeoutExpired:
                            pass

            self._normal_proc = None

            stopped_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
            session["normal"] = {
                **session.get("normal", {}),
                "state": "STOPPED",
                "stopped_at": stopped_at,
                "return_code": proc.returncode,
                "termination_reason": reason,
            }
            for norm in reversed(session.get("normal_history", [])):
                if norm.get("state") == "RUNNING" or norm.get("stopped_at") is None:
                    norm["state"] = "STOPPED"
                    norm["stopped_at"] = stopped_at
                    norm["return_code"] = proc.returncode
                    norm["termination_reason"] = reason
                    break
            return dict(session["normal"])

    def stop_all_simulations(self, session_id: str) -> Dict[str, Any]:
        """Stop all simulations (normal and attack) without stopping the capture session."""
        with self._lock:
            session = self._active_session
            if not session or session["id"] != session_id:
                raise ValueError("Live session not found.")

        attack_res = self.stop_attack(session_id, reason="MANUAL_USER_STOP_ALL")
        normal_res = self.stop_normal(session_id, reason="MANUAL_USER_STOP_ALL")

        return {
            "attack": attack_res,
            "normal": normal_res,
        }

    def stop_attack(self, session_id: str, reason: str = "MANUAL_STOP") -> Dict[str, Any]:
        """Stop only the attack process owned by this manager."""
        with self._lock:
            session = self._active_session

            if not session or session["id"] != session_id:
                raise ValueError("Live session not found.")

            proc = self._attack_proc

            if proc is None:
                return {"state": "NOT_RUNNING"}

            if proc.poll() is None:
                proc.send_signal(signal.SIGINT)

                try:
                    proc.wait(timeout=3.0)
                except subprocess.TimeoutExpired:
                    proc.terminate()
                    try:
                        proc.wait(timeout=2.0)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                        try:
                            proc.wait(timeout=2.0)
                        except subprocess.TimeoutExpired:
                            pass

            self._attack_proc = None

            stopped_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
            session["attack"] = {
                **session.get("attack", {}),
                "state": "STOPPED",
                "stopped_at": stopped_at,
                "return_code": proc.returncode,
                "termination_reason": reason,
            }
            for att in reversed(session.get("attack_history", [])):
                if att.get("state") == "RUNNING" or att.get("stopped_at") is None:
                    att["state"] = "STOPPED"
                    att["stopped_at"] = stopped_at
                    att["return_code"] = proc.returncode
                    att["termination_reason"] = reason
                    break
            session["recovery"] = {
                "state": "ATTACK_STOPPED_VERIFYING",
                "normal_windows": 0,
                "required_normal_windows": 2,
                "stopped_after_window_index": len(session.get("windows", [])) - 1,
            }

            return dict(session["attack"])
    def shutdown(self, timeout: float = 10.0) -> None:
        """Stop capture, drain queued incidents, and shut down the worker."""
        with self._shutdown_lock:
            if self._shutdown_complete:
                return

            if not self._shutdown_requested:
                with self._lock:
                    session = self._active_session
                    session_id = (
                        session["id"]
                        if session and session.get("state") in ("capturing", "stopping")
                        else None
                    )

                if session_id:
                    self.stop_session(session_id)

                # Do not terminate the worker while jobs remain queued.
                self._incident_queue.join()
                self._incident_queue.put(None)
                self._shutdown_requested = True

            self._incident_worker.join(timeout=timeout)
            if self._incident_worker.is_alive():
                raise TimeoutError(
                    "Incident worker did not stop within the shutdown timeout."
                )

            self._shutdown_complete = True

    def _incident_worker_loop(self) -> None:
        """Register and process incidents outside the capture thread."""
        while True:
            job = self._incident_queue.get()
            try:
                if job is None:
                    return

                incident_id = job["incident"]["incident_id"]

                # Prevent duplicate response workers for the same incident
                with self._lock:
                    if incident_id in self._processed_incident_ids:
                        continue
                    self._processed_incident_ids.add(incident_id)

                    # Assess pre-mitigation continuity
                    sniffer_proc = self._sniffer_proc
                    sniffer_pre_alive = (
                        sniffer_proc is not None
                        and getattr(sniffer_proc, "poll", lambda: None)() is None
                    )
                    sniffer_continuity_status = "PASS" if sniffer_pre_alive else "FAIL"

                    normal_proc = self._normal_proc
                    normal_initially_active = (
                        normal_proc is not None
                        and getattr(normal_proc, "poll", lambda: None)() is None
                    )
                    normal_initial_pid = getattr(normal_proc, "pid", None) if normal_initially_active else None

                    target_pid = getattr(self._attack_proc, "pid", None) if self._attack_proc else None

                response_initiated_utc = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

                # Stop only the attack process launched by this manager.
                attack_result = self.stop_attack(job["session_id"], reason="AUTOMATIC_RESPONSE")
                attack_terminated_utc = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

                def _parse_utc_iso(ts):
                    if not ts:
                        return None
                    try:
                        clean = ts.replace("Z", "+00:00")
                        return datetime.fromisoformat(clean)
                    except Exception:
                        return None

                t0 = _parse_utc_iso(job.get("first_anomalous_window_utc"))
                t1 = _parse_utc_iso(job.get("incident_confirmed_utc"))
                t2 = _parse_utc_iso(response_initiated_utc)
                t3 = _parse_utc_iso(attack_terminated_utc)

                detection_ms = round((t1 - t0).total_seconds() * 1000) if (t1 and t0) else None
                mitigation_ms = round((t3 - t2).total_seconds() * 1000) if (t3 and t2) else None
                detection_to_termination_ms = round((t3 - t0).total_seconds() * 1000) if (t3 and t0) else None

                latency_info = {
                    "first_anomalous_window_utc": job.get("first_anomalous_window_utc"),
                    "incident_confirmed_utc": job.get("incident_confirmed_utc"),
                    "response_initiated_utc": response_initiated_utc,
                    "attack_terminated_utc": attack_terminated_utc,
                    "detection_ms": detection_ms,
                    "mitigation_ms": mitigation_ms,
                    "detection_to_termination_ms": detection_to_termination_ms,
                    "attack_mode": job.get("attack_mode"),
                }

                # Evaluate post-mitigation continuity & confirmed process exit
                with self._lock:
                    if normal_initially_active:
                        normal_still_alive = (
                            self._normal_proc is not None
                            and getattr(self._normal_proc, "poll", lambda: None)() is None
                        )
                        normal_pid_preserved = (
                            self._normal_proc is not None
                            and getattr(self._normal_proc, "pid", None) == normal_initial_pid
                        )
                        normal_continuity_status = "PASS" if (normal_still_alive and normal_pid_preserved) else "FAIL"
                    else:
                        normal_continuity_status = "NOT_APPLICABLE"

                    confirmed_mitigation = (attack_result.get("return_code") == 0)
                    final_status = "MITIGATED" if confirmed_mitigation else "FAILED"

                    audit_entry = {
                        "audit_id": f"resp_{uuid.uuid4().hex[:8]}",
                        "incident_id": incident_id,
                        "response_action": "TERMINATE_ATTACK_PROCESS",
                        "process_pid": target_pid,
                        "action_initiation_timestamp": response_initiated_utc,
                        "process_termination_timestamp": attack_terminated_utc,
                        "return_code": attack_result.get("return_code"),
                        "termination_reason": attack_result.get("termination_reason", "AUTOMATIC_RESPONSE"),
                        "sniffer_continuity_status": sniffer_continuity_status,
                        "normal_traffic_continuity_status": normal_continuity_status,
                        "recovery_verification_result": "IN_PROGRESS",
                        "final_response_status": final_status,
                        "detection_latency_ms": detection_ms,
                        "mitigation_latency_ms": mitigation_ms,
                        "total_latency_ms": detection_to_termination_ms,
                    }
                    self._response_audit_trail.append(audit_entry)

                self.analysis_service.register_live_incident(
                    analysis_id=job["analysis_id"],
                    incident=job["incident"],
                    records=job["records"],
                    capture_name=job["capture_name"],
                )

                result = None
                if self._incident_handler is not None:
                    result = self._incident_handler(
                        job["analysis_id"],
                        job["incident"]["incident_id"],
                    )

                with self._lock:
                    session = self._active_session
                    if session and session["id"] == job["session_id"]:
                        session.setdefault("response_audit_trail", []).append(dict(audit_entry))
                        for item in session.get("incidents", []):
                            if item.get("analysis_id") == job["analysis_id"]:
                                item["analysis_registered"] = True
                                item["response_latency"] = latency_info
                                item["response_state"] = (
                                    result.get("status", "REGISTERED")
                                    if isinstance(result, dict)
                                    else "REGISTERED"
                                )
                                if isinstance(result, dict):
                                    item["response_result"] = result
                                break

                        for att in reversed(session.get("attack_history", [])):
                            if att.get("state") == "STOPPED" and att.get("termination_reason") == "AUTOMATIC_RESPONSE":
                                att["incident_id"] = job["incident"]["incident_id"]
                                att["latency"] = latency_info
                                break

            except Exception as exc:
                with self._lock:
                    session = self._active_session
                    if session and session["id"] == job.get("session_id"):
                        for item in session.get("incidents", []):
                            if item.get("analysis_id") == job.get("analysis_id"):
                                item["response_state"] = "ERROR"
                                item["error"] = str(exc)
                                break
            finally:
                self._incident_queue.task_done()

    def get_active_session_snapshot(self, session_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Return a thread-safe snapshot of the requested or active live session."""
        with self._lock:
            if not self._active_session:
                return None
            if session_id and self._active_session["id"] != session_id:
                return None

            s = self._active_session

            # Reconcile child processes that exited or crashed independently
            if self._normal_proc is not None and self._normal_proc.poll() is not None:
                rc = self._normal_proc.returncode
                reason = "PROCESS_CRASH" if rc != 0 else "NATURAL_EXIT"
                stopped_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
                s["normal"] = {
                    **s.get("normal", {}),
                    "state": "STOPPED",
                    "stopped_at": stopped_at,
                    "return_code": rc,
                    "termination_reason": reason,
                }
                for norm in reversed(s.get("normal_history", [])):
                    if norm.get("state") == "RUNNING":
                        norm["state"] = "STOPPED"
                        norm["stopped_at"] = stopped_at
                        norm["return_code"] = rc
                        norm["termination_reason"] = reason
                        break
                self._normal_proc = None

            if self._attack_proc is not None and self._attack_proc.poll() is not None:
                rc = self._attack_proc.returncode
                reason = "PROCESS_CRASH" if rc != 0 else "NATURAL_EXIT"
                stopped_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
                s["attack"] = {
                    **s.get("attack", {}),
                    "state": "STOPPED",
                    "stopped_at": stopped_at,
                    "return_code": rc,
                    "termination_reason": reason,
                }
                for att in reversed(s.get("attack_history", [])):
                    if att.get("state") == "RUNNING":
                        att["state"] = "STOPPED"
                        att["stopped_at"] = stopped_at
                        att["return_code"] = rc
                        att["termination_reason"] = reason
                        break
                self._attack_proc = None

            # Phase 7: Automated Response Validation & Resilience Metrics
            audit_trail = [dict(a) for a in s.get("response_audit_trail", [])]
            incidents = s.get("incidents", [])
            attack_history = s.get("attack_history", [])
            recovery = s.get("recovery", {})
            auto_responses = [a for a in attack_history if a.get("termination_reason") == "AUTOMATIC_RESPONSE"]

            # 1. Confirmed security incident creation
            if incidents:
                chk_incident = {"status": "PASS", "detail": f"{len(incidents)} confirmed incident(s) generated"}
            else:
                chk_incident = {"status": "NOT VERIFIED", "detail": "No confirmed incidents recorded"}

            # 2. Automated response initiation
            if auto_responses or audit_trail:
                chk_initiation = {"status": "PASS", "detail": f"{max(len(auto_responses), len(audit_trail))} response(s) initiated"}
            elif incidents:
                chk_initiation = {"status": "RUNNING", "detail": "Awaiting response initiation"}
            else:
                chk_initiation = {"status": "NOT VERIFIED", "detail": "No response triggers required"}

            # 3. Attack simulator termination
            if auto_responses:
                all_stopped = all(a.get("state") == "STOPPED" for a in auto_responses)
                chk_attack_term = {
                    "status": "PASS" if all_stopped else "FAIL",
                    "detail": f"{len(auto_responses)} attack process(es) terminated",
                }
            elif s.get("attack", {}).get("state") == "RUNNING":
                chk_attack_term = {"status": "RUNNING", "detail": "Attack simulator actively running"}
            else:
                chk_attack_term = {"status": "NOT VERIFIED", "detail": "No attack simulator active"}

            # 4. Actual process exit status (strict return_code == 0 check)
            if auto_responses:
                clean_exits = [a for a in auto_responses if a.get("return_code") == 0]
                if len(clean_exits) == len(auto_responses) and clean_exits:
                    chk_exit_code = {"status": "PASS", "detail": f"All {len(clean_exits)} process(es) confirmed exit code 0"}
                else:
                    chk_exit_code = {"status": "FAIL", "detail": f"{len(auto_responses) - len(clean_exits)} termination(s) non-zero or unconfirmed"}
            else:
                chk_exit_code = {"status": "NOT VERIFIED", "detail": "No attack terminations to verify"}

            # 5. Sniffer process continuity
            sniffer_alive = self._sniffer_proc is not None and self._sniffer_proc.poll() is None
            if s.get("state") == "capturing" and sniffer_alive:
                chk_sniffer = {"status": "PASS", "detail": f"Sniffer active (PID {self._sniffer_proc.pid}, {s.get('frames_captured', 0)} frames)"}
            elif s.get("state") == "capturing" and not sniffer_alive:
                chk_sniffer = {"status": "FAIL", "detail": "Sniffer subprocess exited unexpectedly"}
            else:
                chk_sniffer = {"status": "NOT VERIFIED", "detail": f"Session state: {s.get('state')}"}

            # 6. Normal traffic generator continuity
            normal_state = s.get("normal", {}).get("state")
            normal_rc = s.get("normal", {}).get("return_code")
            if normal_state == "RUNNING" and self._normal_proc is not None and self._normal_proc.poll() is None:
                chk_normal = {"status": "PASS", "detail": f"Normal traffic running continuously (PID {self._normal_proc.pid})"}
            elif normal_rc is not None and normal_rc != 0:
                chk_normal = {"status": "FAIL", "detail": f"Normal generator crashed with exit code {normal_rc}"}
            else:
                chk_normal = {"status": "NOT VERIFIED", "detail": "Normal generator not active concurrently"}

            # 7. Consecutive normal-window recovery verification
            rec_state = recovery.get("state", "NOT_STARTED")
            if rec_state == "RECOVERED":
                chk_recovery = {"status": "PASS", "detail": f"Recovery verified ({recovery.get('normal_windows', 2)}/2 consecutive normal windows)"}
            elif rec_state == "ATTACK_STOPPED_VERIFYING":
                chk_recovery = {"status": "RUNNING", "detail": f"Verifying ({recovery.get('normal_windows', 0)}/2 consecutive normal windows)"}
            else:
                chk_recovery = {"status": "NOT VERIFIED", "detail": f"Recovery state: {rec_state}"}

            all_chk_statuses = [
                chk_incident["status"],
                chk_initiation["status"],
                chk_attack_term["status"],
                chk_exit_code["status"],
                chk_sniffer["status"],
                chk_normal["status"],
                chk_recovery["status"],
            ]
            if "FAIL" in all_chk_statuses:
                overall_validation = "FAIL"
            elif "RUNNING" in all_chk_statuses:
                overall_validation = "RUNNING"
            elif any(st == "PASS" for st in all_chk_statuses):
                overall_validation = "PASS"
            else:
                overall_validation = "NOT VERIFIED"

            # Reliability metrics
            total_attempts = len(audit_trail) if audit_trail else len(auto_responses)
            confirmed_mitigations = len([a for a in auto_responses if a.get("return_code") == 0])
            failed_mitigations = max(0, total_attempts - confirmed_mitigations)
            unexpected_exits = len([a for a in attack_history if a.get("termination_reason") in ("PROCESS_CRASH", "NATURAL_EXIT")])

            if rec_state == "RECOVERED":
                recovery_success_rate = 100.0
            elif rec_state == "ATTACK_STOPPED_VERIFYING":
                recovery_success_rate = None
            else:
                recovery_success_rate = None

            det_latencies = [
                inc["response_latency"]["detection_ms"]
                for inc in incidents
                if inc.get("response_latency", {}).get("detection_ms") is not None
            ]
            mit_latencies = [
                inc["response_latency"]["mitigation_ms"]
                for inc in incidents
                if inc.get("response_latency", {}).get("mitigation_ms") is not None
            ]
            avg_det_ms = round(sum(det_latencies) / len(det_latencies), 1) if det_latencies else None
            avg_mit_ms = round(sum(mit_latencies) / len(mit_latencies), 1) if mit_latencies else None

            # Return snapshot matching Zod LiveSession schema
            return {
                "id": s["id"],
                "data_source": "backend",
                "state": s["state"],
                "interface": s["interface"],
                "capture_file": s["capture_file"],
                "started_at": s["started_at"],
                "frames_captured": s["frames_captured"],
                "windows": list(s["windows"]),
                "incidents": list(s.get("incidents", [])),
                "normal": dict(s.get("normal", {"state": "NOT_STARTED"})),
                "attack": dict(s.get("attack", {"state": "NOT_STARTED"})),
                "attack_history": [dict(a) for a in s.get("attack_history", [])],
                "normal_history": [dict(n) for n in s.get("normal_history", [])],
                "recovery": dict(s.get("recovery", {
                    "state": "NOT_STARTED",
                    "normal_windows": 0,
                    "required_normal_windows": 2,
                })),
                "response_audit_trail": audit_trail,
                "response_validation": {
                    "overall_status": overall_validation,
                    "checks": {
                        "confirmed_incident_creation": chk_incident,
                        "automated_response_initiation": chk_initiation,
                        "attack_simulator_termination": chk_attack_term,
                        "actual_process_exit_status": chk_exit_code,
                        "sniffer_process_continuity": chk_sniffer,
                        "normal_traffic_continuity": chk_normal,
                        "recovery_verification": chk_recovery,
                    },
                },
                "response_reliability": {
                    "total_response_attempts": total_attempts,
                    "confirmed_successful_mitigations": confirmed_mitigations,
                    "failed_mitigations": failed_mitigations,
                    "unexpected_attack_process_exits": unexpected_exits,
                    "recovery_verification_success_rate": recovery_success_rate,
                    "average_detection_latency_ms": avg_det_ms,
                    "average_mitigation_latency_ms": avg_mit_ms,
                    "average_recovery_duration_ms": None,
                },
                "pending_window_index": s["pending_window_index"],
                "message": s["message"],
            }

    def start_session(
        self,
        interface: str = "vcan0",
        custom_sniffer_cmd: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Start a new live capture session. Raises RuntimeError if one is already running."""
        with self._lock:
            if self._active_session and self._active_session["state"] in ("capturing", "stopping"):
                raise RuntimeError(f"A live capture session ({self._active_session['id']}) is already in progress.")

            # Verify model is available
            if not self.model_path.is_file():
                raise FileNotFoundError(f"Model not found at {self.model_path}")

            bundle = joblib.load(self.model_path)
            model = bundle["model"]
            feature_columns = bundle["feature_columns"]

            session_id = f"live_{uuid.uuid4().hex[:8]}"
            timestamp_str = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            capture_filename = f"live_capture_{session_id}_{timestamp_str}.csv"
            capture_path = self.captures_dir / capture_filename
            started_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

            self._stop_event.clear()
            self._processed_incident_ids.clear()
            self._active_session = {
                "id": session_id,
                "data_source": "backend",
                "state": "capturing",
                "interface": interface,
                "capture_file": str(capture_path),
                "capture_filename": capture_filename,
                "capture_path": capture_path,
                "started_at": started_at,
                "frames_captured": 0,
                "windows": [],
                "incidents": [],
                "normal": {"state": "NOT_STARTED"},
                "attack": {"state": "NOT_STARTED"},
                "attack_history": [],
                "normal_history": [],
                "response_audit_trail": [],
                "recovery": {
                    "state": "NOT_STARTED",
                    "normal_windows": 0,
                    "required_normal_windows": 2,
                    "stopped_after_window_index": None,
                },
                "open_incident_windows": [],
                "open_incident_records": [],
                "incident_records": {},
                "pending_window_index": None,
                "message": "Live capture initialized",
                "records": [],
            }

            # Setup server socket
            # On POSIX: AF_UNIX. If on non-POSIX / testing, allow mocking or AF_INET fallback if specified
            is_posix = hasattr(socket, "AF_UNIX")
            if is_posix:
                try:
                    remove_stale_socket(self.socket_path)
                    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                    server.bind(self.socket_path)
                    try:
                        os.chmod(self.socket_path, 0o600)
                    except OSError:
                        pass
                    server.listen(1)
                    server.settimeout(0.5)
                    self._server_sock = server
                except Exception as exc:
                    self._active_session["state"] = "error"
                    self._active_session["message"] = f"Socket bind error: {exc}"
                    raise RuntimeError(f"Failed to bind Unix domain socket {self.socket_path}: {exc}")
            else:
                self._server_sock = None  # On Windows, socket receiver can be mocked or fed directly in tests

            # Launch sniffer process if executable exists and not in simulated test
            if custom_sniffer_cmd:
                cmd = custom_sniffer_cmd
            elif self.sniffer_path.is_file() and os.access(self.sniffer_path, os.X_OK):
                cmd = [str(self.sniffer_path), "--socket"]
            else:
                cmd = None

            if cmd:
                try:
                    self._sniffer_proc = subprocess.Popen(
                        cmd,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.PIPE,
                    )
                except Exception as exc:
                    self._cleanup_socket()
                    self._active_session["state"] = "error"
                    self._active_session["message"] = f"Failed to start sniffer: {exc}"
                    raise RuntimeError(f"Could not execute sniffer {cmd}: {exc}")
            else:
                self._sniffer_proc = None

            # Spawn receiver thread
            self._receiver_thread = threading.Thread(
                target=self._receiver_worker,
                args=(session_id, model, feature_columns, capture_path),
                daemon=True,
                name=f"CANLiveReceiver-{session_id}",
            )
            self._receiver_thread.start()

            return self.get_active_session_snapshot(session_id)

    def _receiver_worker(
        self,
        session_id: str,
        model: Any,
        feature_columns: List[str],
        capture_path: Path,
    ):
        """Worker thread processing incoming socket frames or test events."""
        server = self._server_sock
        conn = None

        anchor_ns: Optional[int] = None
        current_index: Optional[int] = None
        current_window_records: List[Dict[str, Any]] = []
        all_records: List[Dict[str, Any]] = []
        prev_ts_ns: Optional[int] = None

        # Prepare capture CSV
        try:
            csv_handle = capture_path.open("w", newline="", encoding="utf-8")
            csv_writer = csv.writer(csv_handle, lineterminator="\n")
            csv_writer.writerow(EXPECTED_HEADER)
            csv_handle.flush()
        except Exception as exc:
            with self._lock:
                if self._active_session and self._active_session["id"] == session_id:
                    self._active_session["state"] = "error"
                    self._active_session["message"] = f"Failed to create capture CSV: {exc}"
            return

        try:
            # Wait for client connection if server socket is active
            if server:
                while not self._stop_event.is_set():
                    try:
                        conn, _ = server.accept()
                        break
                    except socket.timeout:
                        continue
                    except OSError:
                        break

            buffer = b""
            while not self._stop_event.is_set():
                if conn:
                    try:
                        conn.settimeout(0.5)
                        chunk = conn.recv(4096)
                        if not chunk:
                            # Client closed connection
                            break
                        buffer += chunk
                        while b"\n" in buffer:
                            line, buffer = buffer.split(b"\n", 1)
                            if not line:
                                continue
                            raw_event = json.loads(line.decode("utf-8"))
                            event = validate_event(raw_event)
                            self._process_single_frame(
                                event,
                                session_id,
                                model,
                                feature_columns,
                                csv_writer,
                                csv_handle,
                                all_records,
                                current_window_records,
                            )
                    except socket.timeout:
                        continue
                    except Exception as exc:
                        with self._lock:
                            if self._active_session and self._active_session["id"] == session_id:
                                self._active_session["message"] = f"Stream processing warning: {exc}"
                        break
                else:
                    # No active socket (e.g. running under test or mock injection)
                    time.sleep(0.05)

        finally:
            if conn:
                try:
                    conn.close()
                except Exception:
                    pass
            try:
                csv_handle.close()
            except Exception:
                pass

    def feed_event_direct(
        self,
        event_dict: Dict[str, Any],
        session_id: str,
    ) -> None:
        """Testing seam to feed events directly into live session."""
        with self._lock:
            if not self._active_session or self._active_session["id"] != session_id:
                raise ValueError("Session not found or inactive")
            if self._active_session["state"] != "capturing":
                return

        bundle = joblib.load(self.model_path)
        model = bundle["model"]
        feature_columns = bundle["feature_columns"]

        event = validate_event(event_dict)
        # Append to capture file and process
        with self._lock:
            s = self._active_session
            capture_path = Path(s["capture_file"])
            # Write to CSV
            with capture_path.open("a", newline="", encoding="utf-8") as h:
                writer = csv.writer(h, lineterminator="\n")
                writer.writerow([
                    event["timestamp_utc"],
                    event["interface"],
                    event["can_id"],
                    event["frame_format"],
                    event["flags"],
                    event["dlc"],
                    event["payload"],
                ])

            self._process_single_frame_locked(
                event,
                session_id,
                model,
                feature_columns,
            )

    def _process_single_frame_locked(
        self,
        event: Dict[str, Any],
        session_id: str,
        model: Any,
        feature_columns: List[str],
    ):
        s = self._active_session
        ts_ns = timestamp_to_ns(event["timestamp_utc"])
        identifier = int(event["can_id"], 16)
        record = {
            "timestamp_ns": ts_ns,
            "timestamp_utc": event["timestamp_utc"],
            "interface": event["interface"],
            "can_id": f"0x{identifier:x}",
            "frame_format": event["frame_format"],
            "flags": event.get("flags", "none"),
            "dlc": event.get("dlc", len(event["payload"]) // 2),
            "payload": event["payload"],
        }
        s["records"].append(record)
        s["frames_captured"] += 1

        if not hasattr(self, "_session_anchors"):
            self._session_anchors = {}

        if session_id not in self._session_anchors:
            self._session_anchors[session_id] = {
                "anchor_ns": ts_ns,
                "current_index": 0,
                "current_records": [],
            }

        ctx = self._session_anchors[session_id]
        anchor_ns = ctx["anchor_ns"]
        current_idx = ctx["current_index"]
        window_idx = (ts_ns - anchor_ns) // WINDOW_NS

        if window_idx > current_idx:
            # Score completed window(s)
            self._score_and_record_window(
                model,
                feature_columns,
                ctx["current_records"],
                current_idx,
                anchor_ns,
                s,
            )
            ctx["current_index"] = window_idx
            ctx["current_records"] = []

        ctx["current_records"].append(record)
        s["pending_window_index"] = int(window_idx)

    def _process_single_frame(
        self,
        event: Dict[str, Any],
        session_id: str,
        model: Any,
        feature_columns: List[str],
        csv_writer: Any,
        csv_handle: Any,
        all_records: List[Dict[str, Any]],
        current_window_records: List[Dict[str, Any]],
    ):
        ts_ns = timestamp_to_ns(event["timestamp_utc"])
        identifier = int(event["can_id"], 16)
        record = {
            "timestamp_ns": ts_ns,
            "timestamp_utc": event["timestamp_utc"],
            "interface": event["interface"],
            "can_id": f"0x{identifier:x}",
            "frame_format": event["frame_format"],
            "flags": event.get("flags", "none"),
            "dlc": event.get("dlc", len(event["payload"]) // 2),
            "payload": event["payload"],
        }

        # Write to disk immediately
        csv_writer.writerow([
            event["timestamp_utc"],
            event["interface"],
            event["can_id"],
            event["frame_format"],
            event["flags"],
            event["dlc"],
            event["payload"],
        ])
        csv_handle.flush()

        with self._lock:
            s = self._active_session
            if not s or s["id"] != session_id:
                return

            all_records.append(record)
            s["records"].append(record)
            s["frames_captured"] += 1

            if not hasattr(self, "_session_anchors"):
                self._session_anchors = {}

            if session_id not in self._session_anchors:
                self._session_anchors[session_id] = {
                    "anchor_ns": ts_ns,
                    "current_index": 0,
                    "current_records": current_window_records,
                }

            ctx = self._session_anchors[session_id]
            anchor_ns = ctx["anchor_ns"]
            current_idx = ctx["current_index"]
            window_idx = (ts_ns - anchor_ns) // WINDOW_NS

            if window_idx > current_idx:
                self._score_and_record_window(
                    model,
                    feature_columns,
                    ctx["current_records"],
                    current_idx,
                    anchor_ns,
                    s,
                )
                ctx["current_index"] = window_idx
                ctx["current_records"] = []

            ctx["current_records"].append(record)
            s["pending_window_index"] = int(window_idx)

    def _close_live_incident(self, session_dict: Dict[str, Any]) -> None:
        """Queue a finalized incident for processing outside the capture lock."""
        group = list(session_dict.get("open_incident_windows", []))
        records = list(session_dict.get("open_incident_records", []))

        session_dict["open_incident_windows"] = []
        session_dict["open_incident_records"] = []

        if not group or not records:
            return

        correlated = correlate_incidents(group)
        if not correlated:
            return

        sequence = len(session_dict.get("incidents", [])) + 1
        incident = dict(correlated[0])
        incident["incident_id"] = f"INC-{sequence:04d}"

        analysis_id = (
            f"analysis_live_{session_dict['id']}_incident_{sequence:04d}"
        )
        capture_name = session_dict.get("capture_filename", "live_capture.csv")

        incident_confirmed_utc = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        first_window_utc = group[0]["window_start_utc"] if group else incident_confirmed_utc

        incident_summary = dict(incident)
        incident_summary["analysis_id"] = analysis_id
        incident_summary["analysis_registered"] = False
        incident_summary["response_state"] = "QUEUED"
        incident_summary["response_latency"] = {
            "first_anomalous_window_utc": first_window_utc,
            "incident_confirmed_utc": incident_confirmed_utc,
            "response_initiated_utc": None,
            "attack_terminated_utc": None,
            "detection_ms": None,
            "mitigation_ms": None,
            "detection_to_termination_ms": None,
            "attack_mode": session_dict.get("attack", {}).get("mode"),
        }

        session_dict.setdefault("incidents", []).append(incident_summary)
        session_dict.setdefault("incident_records", {})[analysis_id] = {
            "incident_id": incident["incident_id"],
            "frame_count": len(records),
        }

        self._incident_queue.put({
            "session_id": session_dict["id"],
            "analysis_id": analysis_id,
            "incident": incident,
            "records": records,
            "capture_name": capture_name,
            "first_anomalous_window_utc": first_window_utc,
            "incident_confirmed_utc": incident_confirmed_utc,
            "attack_mode": session_dict.get("attack", {}).get("mode"),
        })

    def _score_and_record_window(
        self,
        model: Any,
        feature_columns: List[str],
        records: List[Dict[str, Any]],
        window_index: int,
        anchor_ns: int,
        session_dict: Dict[str, Any],
    ):
        if not records:
            return

        windows = build_window_features(records, WINDOW_MS)
        if not windows:
            return

        w = windows[0]
        X = [[float(w[col]) for col in feature_columns]]
        pred = int(model.predict(X)[0])
        raw_score = float(model.score_samples(X)[0])
        anom_score = round(-raw_score, 8)
        label = "ANOMALY" if pred == -1 else "NORMAL"
        window_start = ns_to_timestamp(anchor_ns + window_index * WINDOW_NS)

        feats = {col: float(w[col]) for col in FEATURE_COLUMNS}

        # Build response evidence from this live window only.
        id_counts = {}
        for record in records:
            can_id = record["can_id"]
            id_counts[can_id] = id_counts.get(can_id, 0) + 1

        total_frames = sum(id_counts.values())
        dominant_id = (
            max(id_counts, key=lambda can_id: (id_counts[can_id], can_id))
            if id_counts else None
        )
        dominant_share = (
            round(id_counts[dominant_id] / total_frames * 100, 4)
            if dominant_id is not None and total_frames else 0.0
        )

        response_evidence = {
            "can_id_counts": dict(sorted(id_counts.items())),
            "unexpected_can_ids": sorted(
                can_id for can_id in id_counts if can_id not in KNOWN_IDS
            ),
            "dominant_can_id": dominant_id,
            "dominant_can_id_share_pct": dominant_share,
        }

        scored_window = {
            "window_index": int(window_index),
            "window_start_utc": window_start,
            "prediction": label,
            "anomaly_score": anom_score,
            "features": feats,
            "explanation": explain_window(feats, label),
            "response_evidence": response_evidence,
        }
        session_dict["windows"].append(scored_window)

        # Verify recovery only with windows captured after the owned attack stopped.
        recovery = session_dict.setdefault("recovery", {})
        if recovery.get("state") == "ATTACK_STOPPED_VERIFYING":
            stopped_after = recovery.get("stopped_after_window_index")
            if stopped_after is not None and int(window_index) > stopped_after:
                if label == "NORMAL":
                    recovery["normal_windows"] = recovery.get("normal_windows", 0) + 1
                else:
                    recovery["normal_windows"] = 0
                    for audit in session_dict.get("response_audit_trail", []):
                        if audit.get("recovery_verification_result") == "IN_PROGRESS":
                            audit["recovery_verification_result"] = "RESET_BY_ANOMALY"
                    for audit in self._response_audit_trail:
                        if audit.get("recovery_verification_result") == "IN_PROGRESS":
                            audit["recovery_verification_result"] = "RESET_BY_ANOMALY"

                if recovery["normal_windows"] >= recovery.get("required_normal_windows", 2):
                    recovery["state"] = "RECOVERED"
                    recovery["recovery_completed_utc"] = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
                    for audit in session_dict.get("response_audit_trail", []):
                        if audit.get("recovery_verification_result") in ("IN_PROGRESS", "RESET_BY_ANOMALY"):
                            audit["recovery_verification_result"] = "PASS"
                            if audit.get("final_response_status") == "MITIGATED":
                                audit["final_response_status"] = "VERIFIED_RECOVERED"
                    for audit in self._response_audit_trail:
                        if audit.get("recovery_verification_result") in ("IN_PROGRESS", "RESET_BY_ANOMALY"):
                            audit["recovery_verification_result"] = "PASS"
                            if audit.get("final_response_status") == "MITIGATED":
                                audit["final_response_status"] = "VERIFIED_RECOVERED"

        open_windows = session_dict.setdefault("open_incident_windows", [])
        open_records = session_dict.setdefault("open_incident_records", [])

        if label == "ANOMALY":
            # Avoid duplicate incident jobs while a response is pending.
            if session_dict.get("attack_response_queued"):
                return

            if open_windows:
                previous_index = open_windows[-1]["window_index"]
                if int(window_index) != previous_index + 1:
                    if len(open_windows) >= 2:
                        session_dict["attack_response_queued"] = True
                        self._close_live_incident(session_dict)
                        return
                    open_windows.clear()
                    open_records.clear()

            open_windows.append(scored_window)
            open_records.extend(records)

            # Two consecutive anomalous windows trigger automatic response.
            if len(open_windows) >= 2:
                session_dict["attack_response_queued"] = True
                self._close_live_incident(session_dict)
        else:
            if len(open_windows) >= 2 and not session_dict.get("attack_response_queued"):
                session_dict["attack_response_queued"] = True
                self._close_live_incident(session_dict)
            else:
                open_windows.clear()
                open_records.clear()

            # A normal window allows a later incident to be detected.
            session_dict["attack_response_queued"] = False

    def stop_session(self, session_id: str) -> Dict[str, Any]:
        """Stop capture, discard final incomplete window, score all frames, return AnalysisResult."""
        # Stop any simulators owned by this manager.
        self.stop_attack(session_id)
        self.stop_normal(session_id)

        with self._lock:
            if not self._active_session or self._active_session["id"] != session_id:
                raise ValueError(f"Session {session_id} not found or not active")

            s = self._active_session
            s["state"] = "stopping"
            s["message"] = "Stopping sniffer and finalizing analysis"

        self._stop_event.set()

        # Stop sniffer process gracefully
        proc = self._sniffer_proc
        if proc:
            try:
                if proc.poll() is None:
                    proc.send_signal(signal.SIGINT)
                    try:
                        proc.wait(timeout=2.0)
                    except subprocess.TimeoutExpired:
                        proc.terminate()
                        proc.wait(timeout=2.0)
            except Exception:
                pass
            finally:
                self._sniffer_proc = None

        self._cleanup_socket()

        if self._receiver_thread and self._receiver_thread.is_alive():
            self._receiver_thread.join(timeout=3.0)

        with self._lock:
            s = self._active_session
            self._close_live_incident(s)
            if s.get("recovery", {}).get("state") == "ATTACK_STOPPED_VERIFYING":
                s["recovery"]["state"] = "RECOVERY_UNCONFIRMED"
            s["state"] = "stopped"
            records = list(s.get("records", []))
            capture_path = Path(s["capture_file"])
            capture_name = s.get("capture_filename", capture_path.name)
            pending_window_idx = s.get("pending_window_index")

            # Produce complete final AnalysisResult via AnalysisService
            if not records and capture_path.is_file():
                try:
                    from api_analysis_service import parse_csv_records
                    records = parse_csv_records(capture_path)
                except Exception:
                    pass

            analysis_id = f"analysis_live_{session_id}"
            if records:
                analysis_res = self.analysis_service.score_records(
                    records=records,
                    capture_name=capture_name,
                    origin="live",
                    analysis_id=analysis_id,
                )
            else:
                # In case no frames were captured at all
                model_info = get_model_info(self.model_path)
                created_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
                analysis_res = {
                    "id": analysis_id,
                    "data_source": "backend",
                    "capture_file": capture_name,
                    "origin": "live",
                    "created_at": created_at,
                    "frames_loaded": 0,
                    "windows_scored": 0,
                    "normal_count": 0,
                    "anomaly_count": 0,
                    "excluded_partial_window": None,
                    "model": model_info,
                    "windows": [],
                    "frequency_summary": [],
                    "notes": ["Live capture ended with 0 frames recorded."],
                }

            s["message"] = f"Capture stopped. Final analysis: {analysis_res['id']}"
            return analysis_res

    def _cleanup_socket(self):
        if self._server_sock:
            try:
                self._server_sock.close()
            except Exception:
                pass
            self._server_sock = None
        try:
            if hasattr(socket, "AF_UNIX") and Path(self.socket_path).exists():
                Path(self.socket_path).unlink(missing_ok=True)
        except Exception:
            pass
