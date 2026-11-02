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
    from .api_analysis_service import (
        ApiAnalysisService,
        DEFAULT_MODEL_PATH,
        WINDOW_MS,
        format_frequency_row,
        get_model_info,
    )
    from .frequency_analyzer import (
        EXPECTED_HEADER,
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
        socket_path: str = SOCKET_PATH,
    ):
        self.analysis_service = analysis_service
        self.model_path = model_path or DEFAULT_MODEL_PATH
        self.captures_dir = captures_dir or (ROOT / "data")
        self.captures_dir.mkdir(parents=True, exist_ok=True)
        self.sniffer_path = sniffer_path or (ROOT / "build" / "can_sniffer")
        self.socket_path = socket_path

        self._lock = threading.RLock()
        self._active_session: Optional[Dict[str, Any]] = None
        self._sniffer_proc: Optional[subprocess.Popen] = None
        self._server_sock: Optional[socket.socket] = None
        self._receiver_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

    def get_active_session_snapshot(self, session_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Return a thread-safe snapshot of the requested or active live session."""
        with self._lock:
            if not self._active_session:
                return None
            if session_id and self._active_session["id"] != session_id:
                return None

            s = self._active_session
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
        session_dict["windows"].append({
            "window_index": int(window_index),
            "window_start_utc": window_start,
            "prediction": label,
            "anomaly_score": anom_score,
            "features": feats,
        })

    def stop_session(self, session_id: str) -> Dict[str, Any]:
        """Stop capture, discard final incomplete window, score all frames, return AnalysisResult."""
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
