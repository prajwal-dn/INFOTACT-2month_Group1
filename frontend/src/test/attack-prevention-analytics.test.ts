/**
 * Phase 4 — Attack Prevention Analytics Tests
 *
 * Tests the pure `deriveAnalytics` function in isolation (no React needed).
 * Covers:
 * 1. Persistent session attack history & repeated attacks.
 * 2. Mixed attack modes (Mode 1 and Mode 2 attributed independently).
 * 3. Normal traffic interruptions (measured strictly via termination reason/crash;
 *    manual stops are NOT interruptions).
 * 4. Successful vs failed termination verification (exit code confirmed).
 * 5. Millisecond response latency calculations.
 * 6. Estimated frame attribution (0x100 shared).
 * 7. Ground truth unavailability for false positives.
 */
import { describe, it, expect } from "vitest";
import { deriveAnalytics } from "@/lib/use-attack-analytics";
import type { LiveSession, LiveAttackRecord, LiveNormalRecord } from "@/lib/api/schemas";

// ─── Helpers ─────────────────────────────────────────────────────────────────

const BASE_TS = "2024-01-15T10:00:00.000Z";

function ts(offsetSeconds: number): string {
  return new Date(Date.parse(BASE_TS) + offsetSeconds * 1000).toISOString();
}

function makeWindow(
  index: number,
  prediction: "NORMAL" | "ANOMALY",
  score: number,
  normalFrames = 30,
  extraId?: string,
  extraFrames = 0
) {
  const third = Math.floor(normalFrames / 3);
  const idCounts: Record<string, number> = {
    "0x100": third,
    "0x101": third,
    "0x102": normalFrames - 2 * third,
  };
  if (extraId && extraFrames > 0) {
    idCounts[extraId] = extraFrames;
  }

  return {
    window_index: index,
    window_start_utc: ts(index),
    prediction,
    anomaly_score: score,
    features: {
      total_frames: normalFrames + extraFrames,
      unique_can_ids: extraId ? 4 : 3,
      extended_frame_count: 0,
      unique_payload_count: 5,
      max_id_share_pct: 50,
      id_0x100_count: third,
      id_0x100_share_pct: 33,
      id_0x101_count: third,
      id_0x101_share_pct: 33,
      id_0x102_count: normalFrames - 2 * third,
      id_0x102_share_pct: 34,
      id_0x999_count: 0,
      id_0x999_share_pct: 0,
      other_id_count: extraFrames,
    },
    response_evidence: {
      can_id_counts: idCounts,
      unexpected_can_ids: extraId ? [extraId] : [],
      dominant_can_id: "0x100",
      dominant_can_id_share_pct: 33,
    },
  };
}

function makeIncident(
  id: string,
  startW: number,
  endW: number,
  severity: "HIGH" | "MEDIUM" | "REVIEW" = "HIGH",
  latency?: {
    first_anomalous_window_utc?: string;
    incident_confirmed_utc?: string;
    response_initiated_utc?: string;
    attack_terminated_utc?: string;
    detection_to_termination_ms?: number;
    detection_ms?: number;
    mitigation_ms?: number;
    attack_mode?: number;
  }
) {
  return {
    incident_id: id,
    severity,
    status: "CONFIRMED",
    start_window: startW,
    end_window: endW,
    window_count: endW - startW + 1,
    start_time_utc: ts(startW),
    end_time_utc: ts(endW),
    affected_can_ids: ["0x100"],
    reasons: [{ code: "HIGH_TRAFFIC_VOLUME", message: "Excessive frames", evidence: {} }],
    summary: "Test incident",
    windows: [],
    analysis_id: `analysis_${id}`,
    analysis_registered: true,
    response_state: "REGISTERED",
    response_latency: latency,
  };
}

function makeSession(overrides: Partial<LiveSession> = {}): LiveSession {
  return {
    id: "live_test01",
    data_source: "backend",
    state: "capturing",
    interface: "vcan0",
    capture_file: "/tmp/test.csv",
    started_at: BASE_TS,
    frames_captured: 0,
    windows: [],
    incidents: [],
    pending_window_index: null,
    message: null,
    normal: { state: "NOT_STARTED" },
    attack: { state: "NOT_STARTED" },
    attack_history: [],
    normal_history: [],
    recovery: { state: "NOT_STARTED", normal_windows: 0, required_normal_windows: 2 },
    ...overrides,
  } as LiveSession;
}

// ─── Tests ────────────────────────────────────────────────────────────────────

describe("deriveAnalytics — empty / idle session", () => {
  it("returns clean empty structure when session is undefined", () => {
    const a = deriveAnalytics(undefined);
    expect(a.totalAttackAttempts).toBe(0);
    expect(a.totalAttacksDetected).toBe(0);
    expect(a.successfulTerminations).toBe(0);
    expect(a.failedTerminations).toBe(0);
    expect(a.avgResponseLatencyMs).toBeNull();
    expect(a.trafficTimeSeries).toHaveLength(0);
    expect(a.latencyPoints).toHaveLength(0);
    expect(a.falsePositiveStatus).toBe("UNAVAILABLE");
  });

  it("returns all zeros for an idle session with no traffic", () => {
    const a = deriveAnalytics(makeSession());
    expect(a.totalAttackAttempts).toBe(0);
    expect(a.totalAttacksDetected).toBe(0);
    expect(a.hasIncidents).toBe(false);
  });
});

describe("deriveAnalytics — persistent per-session attack history & repeated attacks", () => {
  it("counts multiple attack attempts from session attack_history", () => {
    const attackHistory: LiveAttackRecord[] = [
      { attack_id: "att_1", mode: 1, pid: 101, state: "STOPPED", started_at: ts(0), stopped_at: ts(2), return_code: 0, termination_reason: "AUTOMATIC_RESPONSE" },
      { attack_id: "att_2", mode: 2, pid: 102, state: "STOPPED", started_at: ts(5), stopped_at: ts(7), return_code: 0, termination_reason: "AUTOMATIC_RESPONSE" },
      { attack_id: "att_3", mode: 1, pid: 103, state: "RUNNING", started_at: ts(10), stopped_at: null, return_code: null, termination_reason: null },
    ];
    const s = makeSession({ attack_history: attackHistory });
    const a = deriveAnalytics(s);

    expect(a.totalAttackAttempts).toBe(3);
    expect(a.mode1Stats.attempts).toBe(2);
    expect(a.mode2Stats.attempts).toBe(1);
    // att_1 and att_2 stopped cleanly; att_3 still running
    expect(a.successfulTerminations).toBe(2);
    expect(a.failedTerminations).toBe(0);
  });

  it("handles mixed attack modes and attributes stats independently", () => {
    const attackHistory: LiveAttackRecord[] = [
      { attack_id: "att_1", mode: 1, pid: 201, state: "STOPPED", started_at: ts(0), stopped_at: ts(2), return_code: 0, termination_reason: "AUTOMATIC_RESPONSE" },
      { attack_id: "att_2", mode: 1, pid: 202, state: "STOPPED", started_at: ts(5), stopped_at: ts(7), return_code: 1, termination_reason: "PROCESS_CRASH" },
      { attack_id: "att_3", mode: 2, pid: 203, state: "STOPPED", started_at: ts(10), stopped_at: ts(12), return_code: 0, termination_reason: "AUTOMATIC_RESPONSE" },
    ];
    const s = makeSession({
      attack_history: attackHistory,
      incidents: [
        makeIncident("INC-0001", 0, 1, "HIGH", { detection_to_termination_ms: 1200, attack_mode: 1 }),
        makeIncident("INC-0002", 10, 11, "HIGH", { detection_to_termination_ms: 850, attack_mode: 2 }),
      ],
    });
    const a = deriveAnalytics(s);

    expect(a.totalAttackAttempts).toBe(3);
    expect(a.mode1Stats.attempts).toBe(2);
    expect(a.mode1Stats.successfulTerminations).toBe(1);
    expect(a.mode1Stats.failedTerminations).toBe(1);
    expect(a.mode1Stats.detected).toBe(1);
    expect(a.mode1Stats.avgLatencyMs).toBe(1200);

    expect(a.mode2Stats.attempts).toBe(1);
    expect(a.mode2Stats.successfulTerminations).toBe(1);
    expect(a.mode2Stats.failedTerminations).toBe(0);
    expect(a.mode2Stats.detected).toBe(1);
    expect(a.mode2Stats.avgLatencyMs).toBe(850);
  });
});

describe("deriveAnalytics — normal traffic interruptions", () => {
  it("does NOT count manual user stop as an interruption", () => {
    const normalHistory: LiveNormalRecord[] = [
      { normal_id: "norm_1", pid: 301, state: "STOPPED", started_at: ts(0), stopped_at: ts(10), return_code: 0, termination_reason: "MANUAL_USER_STOP" },
    ];
    const s = makeSession({
      normal_history: normalHistory,
      incidents: [makeIncident("INC-0001", 1, 2)],
    });
    const a = deriveAnalytics(s);
    expect(a.normalTrafficInterruptions).toBe(0);
  });

  it("does NOT count stop-all simulations or session stop as an interruption", () => {
    const normalHistory: LiveNormalRecord[] = [
      { normal_id: "norm_1", pid: 302, state: "STOPPED", started_at: ts(0), stopped_at: ts(5), return_code: 0, termination_reason: "MANUAL_USER_STOP_ALL" },
      { normal_id: "norm_2", pid: 303, state: "STOPPED", started_at: ts(6), stopped_at: ts(10), return_code: 0, termination_reason: "SESSION_STOP" },
    ];
    const s = makeSession({ normal_history: normalHistory });
    expect(deriveAnalytics(s).normalTrafficInterruptions).toBe(0);
  });

  it("counts process crash or abnormal exit as an interruption", () => {
    const normalHistory: LiveNormalRecord[] = [
      { normal_id: "norm_1", pid: 304, state: "STOPPED", started_at: ts(0), stopped_at: ts(4), return_code: 139, termination_reason: "PROCESS_CRASH" },
    ];
    const s = makeSession({ normal_history: normalHistory });
    expect(deriveAnalytics(s).normalTrafficInterruptions).toBe(1);
  });
});

describe("deriveAnalytics — termination confirmation", () => {
  it("only counts successful termination when process exit is confirmed", () => {
    const attackHistory: LiveAttackRecord[] = [
      { attack_id: "att_1", mode: 1, pid: 401, state: "STOPPED", started_at: ts(0), stopped_at: ts(2), return_code: 0, termination_reason: "AUTOMATIC_RESPONSE" },
    ];
    const s = makeSession({ attack_history: attackHistory });
    const a = deriveAnalytics(s);
    expect(a.successfulTerminations).toBe(1);
    expect(a.failedTerminations).toBe(0);
  });

  it("counts failed termination when exit code is non-zero", () => {
    const attackHistory: LiveAttackRecord[] = [
      { attack_id: "att_1", mode: 1, pid: 402, state: "STOPPED", started_at: ts(0), stopped_at: ts(2), return_code: 1, termination_reason: "TERMINATION_FAILED" },
    ];
    const s = makeSession({ attack_history: attackHistory });
    const a = deriveAnalytics(s);
    expect(a.successfulTerminations).toBe(0);
    expect(a.failedTerminations).toBe(1);
  });

  it("does NOT count termination while attack process is still running", () => {
    const attackHistory: LiveAttackRecord[] = [
      { attack_id: "att_1", mode: 1, pid: 403, state: "RUNNING", started_at: ts(0), stopped_at: null, return_code: null, termination_reason: null },
    ];
    const s = makeSession({ attack_history: attackHistory });
    const a = deriveAnalytics(s);
    expect(a.successfulTerminations).toBe(0);
    expect(a.failedTerminations).toBe(0);
  });
});

describe("deriveAnalytics — response latency in milliseconds", () => {
  it("uses pre-computed backend millisecond latency when available", () => {
    const s = makeSession({
      incidents: [
        makeIncident("INC-0001", 0, 1, "HIGH", {
          first_anomalous_window_utc: "2026-11-10T10:00:00.000Z",
          incident_confirmed_utc: "2026-11-10T10:00:02.000Z",
          response_initiated_utc: "2026-11-10T10:00:02.050Z",
          attack_terminated_utc: "2026-11-10T10:00:02.150Z",
          detection_to_termination_ms: 2150,
          detection_ms: 2000,
          mitigation_ms: 100,
          attack_mode: 1,
        }),
      ],
    });
    const a = deriveAnalytics(s);
    expect(a.avgResponseLatencyMs).toBe(2150);
    expect(a.latencyPoints[0]?.detectionToTerminationMs).toBe(2150);
    expect(a.latencyPoints[0]?.detectionMs).toBe(2000);
    expect(a.latencyPoints[0]?.mitigationMs).toBe(100);
  });

  it("calculates latency in ms from timestamps when pre-computed value is omitted", () => {
    const s = makeSession({
      incidents: [
        makeIncident("INC-0001", 0, 1, "HIGH", {
          first_anomalous_window_utc: "2026-11-10T10:00:00.000Z",
          incident_confirmed_utc: "2026-11-10T10:00:02.000Z",
          response_initiated_utc: "2026-11-10T10:00:02.050Z",
          attack_terminated_utc: "2026-11-10T10:00:03.500Z",
          attack_mode: 2,
        }),
      ],
    });
    const a = deriveAnalytics(s);
    expect(a.avgResponseLatencyMs).toBe(3500);
    expect(a.latencyPoints[0]?.detectionToTerminationMs).toBe(3500);
  });
});

describe("deriveAnalytics — frame attribution & ground truth", () => {
  it("flags frame attribution as estimated due to shared 0x100", () => {
    const s = makeSession({
      windows: [
        makeWindow(0, "NORMAL", 0.05, 90),
        makeWindow(1, "ANOMALY", 0.95, 30, "0x100_flood", 500),
      ],
    });
    const a = deriveAnalytics(s);
    expect(a.isFrameAttributionEstimated).toBe(true);
    expect(a.trafficTimeSeries[0]?.isEstimated).toBe(true);
    expect(a.estimatedNormalFramesDuringAttack).toBe(30);
  });

  it("labels false positives as UNAVAILABLE without fabricating ground truth", () => {
    const s = makeSession({
      windows: [
        makeWindow(0, "NORMAL", 0.05),
        makeWindow(1, "ANOMALY", 0.88), // single window anomaly (no incident)
        makeWindow(2, "NORMAL", 0.04),
      ],
      incidents: [],
    });
    const a = deriveAnalytics(s);
    expect(a.falsePositiveStatus).toBe("UNAVAILABLE");
    expect(a.uncorrelatedAnomalyWindows).toBe(1);
    expect(a.falsePositiveNote).toContain("unavailable");
  });
});
