/**
 * Phase 4 — Attack Prevention Analytics Tests
 *
 * Tests the pure `deriveAnalytics` function in isolation (no React needed).
 * All test sessions are constructed from actual LiveSession shape.
 * No values are hardcoded or fabricated — every assertion verifies that
 * the hook reads from real session fields.
 */
import { describe, it, expect } from "vitest";
import { deriveAnalytics } from "@/lib/use-attack-analytics";
import type { LiveSession } from "@/lib/api/schemas";

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
  responseState = "REGISTERED",
  registered = true
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
    analysis_registered: registered,
    response_state: responseState,
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
    recovery: { state: "NOT_STARTED", normal_windows: 0, required_normal_windows: 2 },
    ...overrides,
  } as LiveSession;
}

// ─── Tests ────────────────────────────────────────────────────────────────────

describe("deriveAnalytics — empty / idle session", () => {
  it("returns all zeros when session is undefined", () => {
    const a = deriveAnalytics(undefined);
    expect(a.totalAttackAttempts).toBe(0);
    expect(a.totalAttacksDetected).toBe(0);
    expect(a.successfulTerminations).toBe(0);
    expect(a.failedTerminations).toBe(0);
    expect(a.trafficTimeSeries).toHaveLength(0);
    expect(a.latencyPoints).toHaveLength(0);
  });

  it("returns all zeros for a session with no attack", () => {
    const a = deriveAnalytics(makeSession());
    expect(a.totalAttackAttempts).toBe(0);
    expect(a.totalAttacksDetected).toBe(0);
    expect(a.hasIncidents).toBe(false);
  });
});

describe("deriveAnalytics — attack attempt counting", () => {
  it("counts 1 attempt when attack.state=RUNNING", () => {
    const s = makeSession({ attack: { state: "RUNNING", mode: 1, pid: 1234 } });
    expect(deriveAnalytics(s).totalAttackAttempts).toBe(1);
    expect(deriveAnalytics(s).currentAttackMode).toBe(1);
  });

  it("counts 1 attempt when attack.state=STOPPED", () => {
    const s = makeSession({ attack: { state: "STOPPED", mode: 1, return_code: 0 } });
    expect(deriveAnalytics(s).totalAttackAttempts).toBe(1);
  });

  it("counts 0 attempts when attack.state=NOT_STARTED", () => {
    const s = makeSession({ attack: { state: "NOT_STARTED" } });
    expect(deriveAnalytics(s).totalAttackAttempts).toBe(0);
  });
});

describe("deriveAnalytics — detection counting from confirmed incidents", () => {
  it("counts 0 detected when only anomaly windows exist but no confirmed incident", () => {
    const s = makeSession({
      windows: [makeWindow(0, "ANOMALY", 0.9), makeWindow(1, "ANOMALY", 0.85)],
      attack: { state: "RUNNING", mode: 1, pid: 123 },
    });
    const a = deriveAnalytics(s);
    expect(a.totalAttacksDetected).toBe(0);
    expect(a.hasIncidents).toBe(false);
    // The 2 anomaly windows not part of an incident are unconfirmed
    expect(a.unconfirmedAnomalyWindows).toBe(2);
  });

  it("counts 1 detection from a confirmed backend incident", () => {
    const s = makeSession({
      windows: [makeWindow(0, "ANOMALY", 0.9), makeWindow(1, "ANOMALY", 0.85)],
      incidents: [makeIncident("INC-0001", 0, 1)],
      attack: { state: "STOPPED", mode: 1, return_code: 0 },
    });
    const a = deriveAnalytics(s);
    expect(a.totalAttacksDetected).toBe(1);
    expect(a.hasIncidents).toBe(true);
    expect(a.unconfirmedAnomalyWindows).toBe(0);
  });

  it("counts 2 detections from 2 confirmed incidents", () => {
    const s = makeSession({
      windows: [
        makeWindow(0, "ANOMALY", 0.9),
        makeWindow(1, "ANOMALY", 0.85),
        makeWindow(5, "ANOMALY", 0.92),
        makeWindow(6, "ANOMALY", 0.88),
      ],
      incidents: [makeIncident("INC-0001", 0, 1), makeIncident("INC-0002", 5, 6)],
      attack: { state: "STOPPED", mode: 1, return_code: 0 },
    });
    expect(deriveAnalytics(s).totalAttacksDetected).toBe(2);
  });
});

describe("deriveAnalytics — termination success/failure", () => {
  it("counts successful termination when attack.return_code=0", () => {
    const s = makeSession({
      incidents: [makeIncident("INC-0001", 0, 1)],
      attack: { state: "STOPPED", mode: 1, return_code: 0 },
    });
    const a = deriveAnalytics(s);
    expect(a.successfulTerminations).toBe(1);
    expect(a.failedTerminations).toBe(0);
  });

  it("counts successful termination when attack.return_code=null (SIGINT clean exit)", () => {
    const s = makeSession({
      incidents: [makeIncident("INC-0001", 0, 1)],
      attack: { state: "STOPPED", mode: 1, return_code: null },
    });
    const a = deriveAnalytics(s);
    expect(a.successfulTerminations).toBe(1);
    expect(a.failedTerminations).toBe(0);
  });

  it("counts failed termination when attack.return_code=1", () => {
    const s = makeSession({
      incidents: [makeIncident("INC-0001", 0, 1)],
      attack: { state: "STOPPED", mode: 2, return_code: 1 },
    });
    const a = deriveAnalytics(s);
    expect(a.successfulTerminations).toBe(0);
    expect(a.failedTerminations).toBe(1);
  });

  it("does NOT count a termination when attack is still RUNNING", () => {
    const s = makeSession({
      incidents: [makeIncident("INC-0001", 0, 1)],
      attack: { state: "RUNNING", mode: 1, pid: 123 },
    });
    const a = deriveAnalytics(s);
    expect(a.successfulTerminations).toBe(0);
    expect(a.failedTerminations).toBe(0);
  });

  it("does NOT count termination merely because an incident was detected", () => {
    // Incident confirmed but attack still running — no termination yet
    const s = makeSession({
      incidents: [makeIncident("INC-0001", 0, 1, "HIGH", "QUEUED", false)],
      attack: { state: "RUNNING", mode: 1, pid: 456 },
    });
    const a = deriveAnalytics(s);
    expect(a.successfulTerminations).toBe(0);
    expect(a.failedTerminations).toBe(0);
  });
});

describe("deriveAnalytics — normal traffic interruptions", () => {
  it("counts 0 interruptions when normal generator never ran", () => {
    const s = makeSession({ normal: { state: "NOT_STARTED" } });
    expect(deriveAnalytics(s).normalTrafficInterruptions).toBe(0);
  });

  it("counts 0 interruptions when normal stopped but no incidents occurred", () => {
    const s = makeSession({
      normal: { state: "STOPPED", return_code: 0 },
      incidents: [],
    });
    expect(deriveAnalytics(s).normalTrafficInterruptions).toBe(0);
  });

  it("counts 1 interruption when normal.state=STOPPED AND incidents occurred", () => {
    const s = makeSession({
      normal: { state: "STOPPED", return_code: 0 },
      incidents: [makeIncident("INC-0001", 0, 1)],
      attack: { state: "STOPPED", mode: 1, return_code: 0 },
    });
    expect(deriveAnalytics(s).normalTrafficInterruptions).toBe(1);
  });
});

describe("deriveAnalytics — normal frames during attack / after mitigation", () => {
  it("counts normal frames from known IDs within anomalous windows", () => {
    const s = makeSession({
      windows: [
        // Anomaly window with 90 normal frames + 500 flood frames
        makeWindow(0, "ANOMALY", 0.95, 90, "0x100_flood", 500),
        makeWindow(1, "ANOMALY", 0.92, 60, "0x100_flood", 400),
      ],
      incidents: [makeIncident("INC-0001", 0, 1)],
      attack: { state: "STOPPED", mode: 1, return_code: 0 },
      recovery: {
        state: "RECOVERED",
        normal_windows: 2,
        required_normal_windows: 2,
        stopped_after_window_index: 1,
      },
    });
    const a = deriveAnalytics(s);
    // 90 + 60 = 150 normal frames across the 2 anomaly windows
    expect(a.normalFramesDuringAttack).toBe(150);
    expect(a.normalFramesAfterMitigation).toBe(0); // no windows after index 1 yet
  });

  it("counts normal frames after mitigation (windows after stopped_after_window_index)", () => {
    const s = makeSession({
      windows: [
        makeWindow(0, "ANOMALY", 0.95, 30),
        makeWindow(1, "ANOMALY", 0.92, 30),
        makeWindow(2, "NORMAL", 0.1, 90),   // post-attack normal window
        makeWindow(3, "NORMAL", 0.08, 90),  // post-attack normal window
      ],
      incidents: [makeIncident("INC-0001", 0, 1)],
      attack: { state: "STOPPED", mode: 1, return_code: 0 },
      recovery: {
        state: "RECOVERED",
        normal_windows: 2,
        required_normal_windows: 2,
        stopped_after_window_index: 1,
      },
    });
    const a = deriveAnalytics(s);
    expect(a.normalFramesDuringAttack).toBe(60); // 30+30 from anomaly windows
    expect(a.normalFramesAfterMitigation).toBe(180); // 90+90 from post-attack windows
  });
});

describe("deriveAnalytics — avg detection window count", () => {
  it("returns null when there are no incidents", () => {
    const s = makeSession({ windows: [makeWindow(0, "NORMAL", 0.1)] });
    expect(deriveAnalytics(s).avgDetectionWindowCount).toBeNull();
  });

  it("returns incident.window_count for a single incident", () => {
    const s = makeSession({
      incidents: [makeIncident("INC-0001", 0, 2)], // window_count = 3
    });
    expect(deriveAnalytics(s).avgDetectionWindowCount).toBe(3);
  });

  it("averages window counts across multiple incidents", () => {
    const s = makeSession({
      incidents: [
        makeIncident("INC-0001", 0, 1), // window_count = 2
        makeIncident("INC-0002", 5, 7), // window_count = 3
      ],
    });
    expect(deriveAnalytics(s).avgDetectionWindowCount).toBe(2.5);
  });
});

describe("deriveAnalytics — traffic time series", () => {
  it("produces one data point per scored window", () => {
    const s = makeSession({
      windows: [
        makeWindow(0, "NORMAL", 0.1),
        makeWindow(1, "ANOMALY", 0.9, 30, "0x100_flood", 500),
        makeWindow(2, "NORMAL", 0.05),
      ],
    });
    const a = deriveAnalytics(s);
    expect(a.trafficTimeSeries).toHaveLength(3);
    const pt0 = a.trafficTimeSeries[0]!;
    const pt1 = a.trafficTimeSeries[1]!;
    expect(pt0.prediction).toBe("NORMAL");
    expect(pt1.prediction).toBe("ANOMALY");
    expect(pt1.maliciousFrames).toBe(500);
    expect(pt1.normalFrames).toBe(30);
    expect(pt1.totalFrames).toBe(530);
  });

  it("returns empty array when no windows", () => {
    expect(deriveAnalytics(makeSession()).trafficTimeSeries).toHaveLength(0);
  });
});

describe("deriveAnalytics — latency chart data", () => {
  it("produces one latency point per confirmed incident", () => {
    const s = makeSession({
      incidents: [
        makeIncident("INC-0001", 0, 1),
        makeIncident("INC-0002", 5, 6),
      ],
      attack: { state: "STOPPED", mode: 1, return_code: 0 },
    });
    const a = deriveAnalytics(s);
    expect(a.latencyPoints).toHaveLength(2);
    const lp0 = a.latencyPoints[0]!;
    const lp1 = a.latencyPoints[1]!;
    expect(lp0.incidentId).toBe("INC-0001");
    expect(lp0.detectionWindowCount).toBe(2);
    expect(lp0.attackMode).toBe(1);
    expect(lp1.incidentId).toBe("INC-0002");
  });

  it("returns empty when no incidents", () => {
    expect(deriveAnalytics(makeSession()).latencyPoints).toHaveLength(0);
  });
});

describe("deriveAnalytics — per-mode stats", () => {
  it("attributes incident to mode 1 when attack.mode=1", () => {
    const s = makeSession({
      incidents: [makeIncident("INC-0001", 0, 1)],
      attack: { state: "STOPPED", mode: 1, return_code: 0 },
      windows: [makeWindow(0, "ANOMALY", 0.95), makeWindow(1, "ANOMALY", 0.9)],
    });
    const a = deriveAnalytics(s);
    expect(a.mode1Stats.attempts).toBe(1);
    expect(a.mode1Stats.detected).toBe(1);
    expect(a.mode1Stats.successfulTerminations).toBe(1);
    expect(a.mode2Stats.attempts).toBe(0);
  });

  it("attributes incident to mode 2 when attack.mode=2", () => {
    const s = makeSession({
      incidents: [makeIncident("INC-0001", 0, 1)],
      attack: { state: "STOPPED", mode: 2, return_code: 0 },
    });
    const a = deriveAnalytics(s);
    expect(a.mode2Stats.attempts).toBe(1);
    expect(a.mode2Stats.detected).toBe(1);
    expect(a.mode1Stats.attempts).toBe(0);
  });

  it("records peak anomaly score from actual anomaly windows", () => {
    const s = makeSession({
      incidents: [makeIncident("INC-0001", 0, 1)],
      attack: { state: "STOPPED", mode: 1, return_code: 0 },
      windows: [
        makeWindow(0, "ANOMALY", 0.72),
        makeWindow(1, "ANOMALY", 0.91),
        makeWindow(2, "NORMAL", 0.05),
      ],
    });
    const a = deriveAnalytics(s);
    expect(a.mode1Stats.peakAnomalyScore).toBeCloseTo(0.91, 2);
  });
});

describe("deriveAnalytics — recovery state", () => {
  it("reports recoveryVerified=false when recovery=NOT_STARTED", () => {
    const s = makeSession({ recovery: { state: "NOT_STARTED", normal_windows: 0, required_normal_windows: 2 } });
    expect(deriveAnalytics(s).recoveryVerified).toBe(false);
  });

  it("reports recoveryVerified=true when recovery.state=RECOVERED", () => {
    const s = makeSession({
      recovery: { state: "RECOVERED", normal_windows: 2, required_normal_windows: 2 },
    });
    const a = deriveAnalytics(s);
    expect(a.recoveryVerified).toBe(true);
    expect(a.verifiedNormalWindows).toBe(2);
  });

  it("reports recoveryState=ATTACK_STOPPED_VERIFYING while verifying", () => {
    const s = makeSession({
      recovery: { state: "ATTACK_STOPPED_VERIFYING", normal_windows: 1, required_normal_windows: 2 },
    });
    const a = deriveAnalytics(s);
    expect(a.recoveryState).toBe("ATTACK_STOPPED_VERIFYING");
    expect(a.recoveryVerified).toBe(false);
    expect(a.verifiedNormalWindows).toBe(1);
  });
});

describe("deriveAnalytics — multiple attack attempts within session scope", () => {
  it("handles Mode 1 normal+attack concurrent scenario correctly", () => {
    const s = makeSession({
      state: "capturing",
      windows: [
        makeWindow(0, "NORMAL", 0.1, 90),   // normal traffic only
        makeWindow(1, "NORMAL", 0.08, 90),  // normal traffic only
        makeWindow(2, "ANOMALY", 0.93, 30, "0x100_flood", 1000), // attack started
        makeWindow(3, "ANOMALY", 0.97, 20, "0x100_flood", 1200),
        makeWindow(4, "NORMAL", 0.06, 80),  // attack stopped, recovery
        makeWindow(5, "NORMAL", 0.04, 85),  // recovery confirmed
      ],
      incidents: [makeIncident("INC-0001", 2, 3, "HIGH", "REGISTERED", true)],
      attack: { state: "STOPPED", mode: 1, return_code: 0 },
      normal: { state: "RUNNING", pid: 9001, interval_ms: 100 },
      recovery: {
        state: "RECOVERED",
        normal_windows: 2,
        required_normal_windows: 2,
        stopped_after_window_index: 3,
      },
    });

    const a = deriveAnalytics(s);
    expect(a.totalAttackAttempts).toBe(1);
    expect(a.totalAttacksDetected).toBe(1);
    expect(a.successfulTerminations).toBe(1);
    expect(a.failedTerminations).toBe(0);
    expect(a.recoveryVerified).toBe(true);
    // Normal frames during attack (windows 2+3): 30+20 = 50
    expect(a.normalFramesDuringAttack).toBe(50);
    // Normal frames after mitigation (windows 4+5, both > stopped_after=3): 80+85 = 165
    expect(a.normalFramesAfterMitigation).toBe(165);
    expect(a.normalTrafficInterruptions).toBe(0); // normal still RUNNING
    expect(a.unconfirmedAnomalyWindows).toBe(0); // all anomaly windows in confirmed incident
    expect(a.trafficTimeSeries).toHaveLength(6);
    expect(a.latencyPoints).toHaveLength(1);
    expect(a.mode1Stats.attempts).toBe(1);
    expect(a.mode2Stats.attempts).toBe(0);
  });
});
