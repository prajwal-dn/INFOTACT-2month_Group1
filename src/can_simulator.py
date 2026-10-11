#!/usr/bin/env python3
"""Generate correlated, simulated vehicle CAN traffic on a Linux SocketCAN interface.

CAN-Sentinel educational simulator
----------------------------------
Default interface: vcan0 (virtual CAN; no physical vehicle is contacted).

Setup on Kali/Debian:
    sudo apt update
    sudo apt install -y can-utils iproute2 python3-can
    sudo modprobe vcan
    sudo ip link show vcan0 >/dev/null 2>&1 || sudo ip link add dev vcan0 type vcan
    sudo ip link set up vcan0

Run:
    python3 src/can_simulator.py --channel vcan0 --verbose
    candump vcan0  # in another terminal

Frames use standard 11-bit CAN identifiers and 8-byte payloads:
    0x100 Engine RPM: bytes 0-1, little-endian raw = RPM / 0.25
    0x101 Vehicle speed: bytes 0-1, little-endian raw = km/h / 0.01
    0x102 Coolant temperature: byte 0, raw = degrees C + 40
    All frames: byte 6 low nibble = rolling counter; byte 7 = XOR of bytes 0-6.

The XOR byte is an educational application-level checksum for this simulation. It is
NOT the CRC used by the actual CAN data-link layer. --fault-rate optionally corrupts
this byte for controlled detector tests. Leave it at 0 for normal baseline collection.
"""

from __future__ import annotations

import argparse
import logging
import math
import random
import signal
import struct
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

import can

LOG = logging.getLogger("can-sim")

ENGINE_RPM_ID = 0x100
VEHICLE_SPEED_ID = 0x101
COOLANT_TEMP_ID = 0x102

IDLE_RPM = 800.0
MAX_RPM = 6_500.0
MAX_SPEED_KMH = 180.0
# Simplified RPM-per-km/h ratios for gears 1 through 5.
GEAR_RATIOS = (110.0, 62.0, 42.0, 31.0, 24.0)
GEAR_UP_THRESHOLDS_KMH = (20.0, 40.0, 65.0, 95.0)


def clamp_int(value: float, low: int, high: int) -> int:
    """Round and clamp a numeric value to an inclusive integer range."""
    return max(low, min(high, int(round(value))))


def xor_checksum(payload: bytes) -> int:
    """Return XOR over the first seven bytes of an 8-byte simulated payload."""
    result = 0
    for byte in payload[:7]:
        result ^= byte
    return result


def finalize_payload(signal_bytes: bytes, counter: int, corrupt_checksum: bool = False) -> bytes:
    """Build an exactly eight-byte payload with counter and simulated checksum.

    Signal data occupies bytes 0-5 (unused positions are zero-filled), byte 6
    contains the rolling counter, and byte 7 contains the XOR checksum.
    """
    if len(signal_bytes) > 6:
        raise ValueError("Signal encoder must return no more than 6 bytes")

    payload = bytearray(signal_bytes[:6].ljust(6, b"\x00"))
    payload.append(counter & 0x0F)
    payload.append(xor_checksum(payload))

    if corrupt_checksum:
        payload[7] ^= 0xFF

    return bytes(payload)


@dataclass
class VehicleState:
    """Small correlated model of speed, engine RPM and coolant temperature."""

    speed_kmh: float = 0.0
    rpm: float = IDLE_RPM
    coolant_c: float = 60.0
    target_speed_kmh: float = 0.0
    next_target_change_s: float = 0.0

    def update(self, dt_s: float, elapsed_s: float) -> None:
        """Advance the simple vehicle model by ``dt_s`` seconds."""
        if dt_s <= 0.0:
            return

        # Change the desired speed every 5-15 seconds to simulate driving phases.
        if elapsed_s >= self.next_target_change_s:
            self.target_speed_kmh = random.choice((0.0, 30.0, 50.0, 80.0, 110.0, 130.0))
            self.next_target_change_s = elapsed_s + random.uniform(5.0, 15.0)

        # Accelerate and brake smoothly; values are in km/h per second.
        acceleration = 6.0 if self.target_speed_kmh > self.speed_kmh else -9.0
        speed_step = acceleration * dt_s
        remaining = self.target_speed_kmh - self.speed_kmh
        if abs(remaining) <= abs(speed_step):
            self.speed_kmh = self.target_speed_kmh
        else:
            self.speed_kmh += speed_step
        self.speed_kmh = min(max(self.speed_kmh, 0.0), MAX_SPEED_KMH)

        # Engine RPM roughly follows road speed and a simplified gear selection.
        gear_index = sum(self.speed_kmh >= threshold for threshold in GEAR_UP_THRESHOLDS_KMH)
        desired_rpm = max(IDLE_RPM, self.speed_kmh * GEAR_RATIOS[gear_index])
        desired_rpm += random.uniform(-40.0, 40.0)
        smoothing = min(1.0, 5.0 * dt_s)
        self.rpm += (desired_rpm - self.rpm) * smoothing
        self.rpm = min(max(self.rpm, IDLE_RPM - 50.0), MAX_RPM)

        # Coolant changes slowly compared with RPM/speed (roughly 30 s time constant).
        target_coolant = 90.0 + max(0.0, self.rpm - IDLE_RPM) / 1_500.0
        thermal_alpha = min(1.0, dt_s / 30.0)
        self.coolant_c += (target_coolant - self.coolant_c) * thermal_alpha
        self.coolant_c = min(max(self.coolant_c, -40.0), 150.0)


@dataclass
class Signal:
    """A CAN signal/frame definition and its independent transmission schedule."""

    can_id: int
    period_s: float
    encode: Callable[[], bytes]
    describe: Callable[[], str]
    counter: int = 0
    next_due_s: float = 0.0


def build_signals(state: VehicleState, rpm_period_s: float,
                  speed_period_s: float, coolant_period_s: float) -> list[Signal]:
    """Create the project's three simulated ECU signals."""
    return [
        Signal(
            can_id=ENGINE_RPM_ID,
            period_s=rpm_period_s,
            encode=lambda: struct.pack("<H", clamp_int(state.rpm / 0.25, 0, 0xFFFF)),
            describe=lambda: f"Engine RPM: {state.rpm:7.1f}",
        ),
        Signal(
            can_id=VEHICLE_SPEED_ID,
            period_s=speed_period_s,
            encode=lambda: struct.pack("<H", clamp_int(state.speed_kmh / 0.01, 0, 0xFFFF)),
            describe=lambda: f"Speed: {state.speed_kmh:6.2f} km/h",
        ),
        Signal(
            can_id=COOLANT_TEMP_ID,
            period_s=coolant_period_s,
            encode=lambda: bytes([clamp_int(state.coolant_c + 40.0, 0, 255)]),
            describe=lambda: f"Coolant: {state.coolant_c:5.1f} C",
        ),
    ]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate simulated RPM, speed and coolant CAN frames on SocketCAN."
    )
    parser.add_argument("-c", "--channel", default="vcan0", help="SocketCAN interface (default: vcan0)")
    parser.add_argument("-d", "--duration", type=float, default=0.0,
                        help="Stop after N seconds; 0 means run until Ctrl+C (default: 0)")
    parser.add_argument("--seed", type=int, help="Random seed for repeatable simulations")
    parser.add_argument("--fault-rate", type=float, default=0.0,
                        help="Probability [0,1] of corrupting simulated checksum; default 0")
    parser.add_argument("--rpm-period", type=float, default=0.1,
                        help="RPM frame period in seconds (default: 0.1)")
    parser.add_argument("--speed-period", type=float, default=0.1,
                        help="Speed frame period in seconds (default: 0.1)")
    parser.add_argument("--coolant-period", type=float, default=1.0,
                        help="Coolant frame period in seconds (default: 1.0)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Log every transmitted frame")
    args = parser.parse_args()

    if not math.isfinite(args.duration) or args.duration < 0.0:
        parser.error("--duration must be a finite, non-negative number")
    if not math.isfinite(args.fault_rate) or not 0.0 <= args.fault_rate <= 1.0:
        parser.error("--fault-rate must be between 0 and 1")
    for option in ("rpm_period", "speed_period", "coolant_period"):
        value = getattr(args, option)
        if not math.isfinite(value) or value <= 0.0:
            parser.error(f"--{option.replace('_', '-')} must be a finite number greater than 0")
    if not args.channel or any(ch.isspace() for ch in args.channel):
        parser.error("--channel must be a non-empty interface name without whitespace")

    return args


def main() -> int:
    args = parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )

    if args.seed is not None:
        random.seed(args.seed)

    # Report a clear setup error before asking python-can to open a missing interface.
    if not Path("/sys/class/net", args.channel).exists():
        LOG.error("CAN interface '%s' was not found.", args.channel)
        LOG.error("For vcan0, run: sudo modprobe vcan; sudo ip link add dev vcan0 type vcan; sudo ip link set up vcan0")
        return 1

    state = VehicleState()
    signals = build_signals(state, args.rpm_period, args.speed_period, args.coolant_period)
    frame_count = 0
    running = True

    def request_stop(_signum: int, _frame: object) -> None:
        nonlocal running
        running = False

    signal.signal(signal.SIGINT, request_stop)
    signal.signal(signal.SIGTERM, request_stop)

    try:
        with can.Bus(interface="socketcan", channel=args.channel) as bus:
            start_s = time.monotonic()
            last_s = start_s
            for item in signals:
                item.next_due_s = start_s

            LOG.info("Simulator running on %s; Ctrl+C to stop.", args.channel)
            LOG.info("Frame periods: RPM=%gs, speed=%gs, coolant=%gs; checksum fault rate=%.3f",
                     args.rpm_period, args.speed_period, args.coolant_period, args.fault_rate)

            while running:
                now_s = time.monotonic()
                elapsed_s = now_s - start_s
                if args.duration > 0.0 and elapsed_s >= args.duration:
                    break

                dt_s = now_s - last_s
                state.update(dt_s, elapsed_s)
                last_s = now_s

                for item in signals:
                    if now_s < item.next_due_s:
                        continue

                    corrupt = random.random() < args.fault_rate
                    signal_bytes = item.encode()
                    payload = finalize_payload(signal_bytes, item.counter, corrupt)
                    message = can.Message(
                        arbitration_id=item.can_id,
                        data=payload,
                        is_extended_id=False,
                    )
                    bus.send(message)
                    frame_count += 1
                    item.counter = (item.counter + 1) & 0x0F

                    # Advance from the planned schedule, not from send time, to limit drift.
                    item.next_due_s += item.period_s
                    # If the process was paused or delayed, skip missed periods instead of
                    # emitting a burst of stale frames to catch up.
                    if item.next_due_s <= now_s:
                        missed_periods = math.floor((now_s - item.next_due_s) / item.period_s) + 1
                        item.next_due_s += missed_periods * item.period_s

                    LOG.debug("ID=0x%03X | %-28s | data=%s%s",
                              item.can_id, item.describe(), payload.hex(" "),
                              " [BAD SIMULATED CHECKSUM]" if corrupt else "")

                next_due = min(item.next_due_s for item in signals)
                sleep_s = max(0.0, min(0.01, next_due - time.monotonic()))
                time.sleep(sleep_s)

    except (can.CanError, OSError, ValueError) as exc:
        LOG.error("Could not run CAN simulator on '%s': %s", args.channel, exc)
        LOG.error("Confirm that the interface exists and is up: ip link show %s", args.channel)
        return 1

    LOG.info("Simulator stopped. Total frames sent: %d", frame_count)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
