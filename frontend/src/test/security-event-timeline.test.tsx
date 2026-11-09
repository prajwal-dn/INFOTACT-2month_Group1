/**
 * Tests for useSecurityTimeline / SecurityEventTimeline (Phase 2)
 */
import { describe, it, expect } from "vitest";
import { renderHook } from "@testing-library/react";
import { deriveEvents, useSecurityTimeline } from "@/lib/use-security-timeline";
import type { LiveSession } from "@/lib/api/schemas";

// ─── Fixtures ────────────────────────────────────────────────────────────────

function makeWindow(
  index: number,
  prediction: "NORMAL" | "ANOMALY",
  ts = `2025-01-15T10:${String(index).padStart(2, "0")}:00.000Z`,
  score = prediction === "ANOMALY" ? -0.25 : 0.1,
  canIds: Record<string, number> = {},
) {
  return {
    window_index: index,
    window_start_utc: ts,
    prediction,
    anomaly_score: score,
    features: {
      total_frames: 120,
      unique_can_ids: 3,
      extended_frame_count: 0,
      unique_payload_count: 5,
      max_id_share_pct: 60,
      id_0x100_count: 70,
      id_0x100_share_pct: 58,
      id_0x101_count: 30,
      id_0x101_share_pct: 25,
      id_0x102_count: 20,
      id_0x102_share_pct: 17,
      id_0x999_count: 0,
      id_0x999_share_pct: 0,
      other_id_count: 0,
    } as const,
    response_evidence: Object.keys(canIds).length
      ? { can_id_counts: canIds, unexpected_can_ids: Object.keys(canIds), dominant_can_id: null, dominant_can_id_share_pct: 0 }
      : undefined,
  };
}

function makeIncident(id: string, severity: "HIGH" | "MEDIUM" | "REVIEW" = "HIGH") {
  return {
    incident_id: id,
    severity,
    status: "CONFIRMED",
    start_window: 3,
    end_window: 5,
    window_count: 3,
    start_time_utc: "2025-01-15T10:03:00.000Z",
    end_time_utc: "2025-01-15T10:05:00.000Z",
    affected_can_ids: ["0x999"],
    response_evidence: undefined,
    reasons: [],
    windows: [],
    summary: "High-volume injection from 0x999",
    response_state: "INITIATED",
    response_result: undefined,
    analysis_id: undefined,
    analysis_registered: false,
  };
}

const BASE_SESSION: LiveSession = {
  id: "sess-abc123",
  data_source: "backend",
  state: "capturing",
  interface: "vcan0",
  capture_file: "/tmp/cap.bin",
  started_at: "2025-01-15T10:00:00.000Z",
  frames_captured: 1200,
  windows: [],
  pending_window_index: null,
  message: null,
  incidents: [],
  attack: { state: "NOT_STARTED" },
  recovery: { state: "NOT_STARTED" },
};

// ─── deriveEvents (pure function) tests ──────────────────────────────────────

describe("deriveEvents", () => {
  it("returns empty array when session is undefined", () => {
    expect(deriveEvents(undefined)).toEqual([]);
  });

  it("always emits a monitoring-started event", () => {
    const events = deriveEvents({ ...BASE_SESSION });
    const start = events.find((e) => e.id === `start:${BASE_SESSION.id}`);
    expect(start).toBeDefined();
    expect(start!.category).toBe("system");
    expect(start!.severity).toBe("info");
    expect(start!.timestamp).toBe(BASE_SESSION.started_at);
  });

  it("emits anomaly event for each ANOMALY window with score and CAN IDs", () => {
    const session: LiveSession = {
      ...BASE_SESSION,
      windows: [
        makeWindow(0, "NORMAL"),
        makeWindow(1, "ANOMALY", "2025-01-15T10:01:00.000Z", -0.3, { "0x999": 50 }),
      ],
    };
    const events = deriveEvents(session);
    const anomaly = events.find((e) => e.id === `anomaly:${session.id}:1`);
    expect(anomaly).toBeDefined();
    expect(anomaly!.category).toBe("anomaly");
    expect(anomaly!.severity).toBe("warning");
    expect(anomaly!.score).toBeCloseTo(-0.3);
    expect(anomaly!.can_ids).toContain("0x999");
  });

  it("batches normal windows into summary every 5", () => {
    const windows = Array.from({ length: 10 }, (_, i) => makeWindow(i, "NORMAL"));
    const session: LiveSession = { ...BASE_SESSION, windows };
    const events = deriveEvents(session);

    const normalSummaries = events.filter((e) => e.category === "normal");
    // 10 normal windows → 2 summaries (at window 4 and 9)
    expect(normalSummaries.length).toBe(2);
  });

  it("emits incident-confirmed event with incident_id and severity", () => {
    const inc = makeIncident("INC-001", "HIGH");
    const session: LiveSession = {
      ...BASE_SESSION,
      incidents: [inc],
      windows: [makeWindow(3, "ANOMALY"), makeWindow(4, "ANOMALY"), makeWindow(5, "ANOMALY")],
    };
    const events = deriveEvents(session);
    const incEvent = events.find((e) => e.id === `incident:INC-001`);
    expect(incEvent).toBeDefined();
    expect(incEvent!.category).toBe("incident");
    expect(incEvent!.severity).toBe("critical"); // HIGH → critical
    expect(incEvent!.incident_id).toBe("INC-001");
    expect(incEvent!.can_ids).toContain("0x999");
  });

  it("emits response-initiated event when response_state is not QUEUED", () => {
    const inc = makeIncident("INC-002");
    const session: LiveSession = { ...BASE_SESSION, incidents: [inc] };
    const events = deriveEvents(session);
    const respEvent = events.find((e) => e.id === `response-initiated:INC-002`);
    expect(respEvent).toBeDefined();
    expect(respEvent!.category).toBe("response");
  });

  it("emits attack-stopped event when attack.state === STOPPED", () => {
    const session: LiveSession = {
      ...BASE_SESSION,
      windows: Array.from({ length: 6 }, (_, i) => makeWindow(i, i < 3 ? "NORMAL" : "ANOMALY")),
      attack: { state: "STOPPED", pid: 1234, return_code: 0 },
      recovery: { state: "ATTACK_STOPPED_VERIFYING", normal_windows: 1, required_normal_windows: 2, stopped_after_window_index: 5 },
    };
    const events = deriveEvents(session);
    const stopped = events.find((e) => e.id === `attack-stopped:${session.id}`);
    expect(stopped).toBeDefined();
    expect(stopped!.title).toContain("terminated");
  });

  it("emits recovery-started event when recovery.state is ATTACK_STOPPED_VERIFYING", () => {
    const session: LiveSession = {
      ...BASE_SESSION,
      incidents: [makeIncident("INC-003")],
      attack: { state: "STOPPED", return_code: 0 },
      recovery: { state: "ATTACK_STOPPED_VERIFYING", normal_windows: 1, required_normal_windows: 2, stopped_after_window_index: 2 },
      windows: [makeWindow(0, "NORMAL"), makeWindow(1, "ANOMALY"), makeWindow(2, "ANOMALY"), makeWindow(3, "NORMAL")],
    };
    const events = deriveEvents(session);
    const rec = events.find((e) => e.id === `recovery-started:${session.id}`);
    expect(rec).toBeDefined();
    expect(rec!.category).toBe("recovery");
  });

  it("emits recovery-verified event when recovery.state is RECOVERED", () => {
    const session: LiveSession = {
      ...BASE_SESSION,
      incidents: [makeIncident("INC-004")],
      attack: { state: "STOPPED", return_code: 0 },
      recovery: { state: "RECOVERED", normal_windows: 2, required_normal_windows: 2, stopped_after_window_index: 3 },
      windows: [
        makeWindow(0, "NORMAL"),
        makeWindow(1, "ANOMALY"),
        makeWindow(2, "ANOMALY"),
        makeWindow(3, "ANOMALY"),
        makeWindow(4, "NORMAL"),
        makeWindow(5, "NORMAL"),
      ],
    };
    const events = deriveEvents(session);
    const verified = events.find((e) => e.id === `recovered:${session.id}`);
    expect(verified).toBeDefined();
    expect(verified!.category).toBe("recovery");
    expect(verified!.severity).toBe("normal");
    expect(verified!.title).toContain("verified");
  });

  it("produces no duplicate events when called twice with the same session object", () => {
    const session: LiveSession = {
      ...BASE_SESSION,
      windows: [makeWindow(0, "ANOMALY")],
      incidents: [makeIncident("INC-005")],
    };
    const first = deriveEvents(session);
    const second = deriveEvents(session);

    // IDs must be unique within each call
    const firstIds = first.map((e) => e.id);
    expect(new Set(firstIds).size).toBe(firstIds.length);

    // Both calls must yield the same events
    expect(first.map((e) => e.id)).toEqual(second.map((e) => e.id));
  });

  it("events are sorted oldest-first by timestamp", () => {
    const session: LiveSession = {
      ...BASE_SESSION,
      windows: [makeWindow(0, "NORMAL"), makeWindow(1, "ANOMALY")],
      incidents: [makeIncident("INC-006")],
    };
    const events = deriveEvents(session);
    const timestamps = events.map((e) => e.timestamp);
    const sorted = [...timestamps].sort();
    expect(timestamps).toEqual(sorted);
  });
});

// ─── useSecurityTimeline hook tests ──────────────────────────────────────────

describe("useSecurityTimeline", () => {
  it("returns empty array for undefined session", () => {
    const { result } = renderHook(() => useSecurityTimeline(undefined));
    expect(result.current).toEqual([]);
  });

  it("memoises result — same reference when session object is unchanged", () => {
    const session: LiveSession = { ...BASE_SESSION };
    const { result, rerender } = renderHook(({ s }: { s: LiveSession }) => useSecurityTimeline(s), {
      initialProps: { s: session },
    });
    const first = result.current;
    rerender({ s: session }); // same object reference
    expect(result.current).toBe(first); // referential equality
  });

  it("produces new array when windows are added", () => {
    const session1: LiveSession = { ...BASE_SESSION, windows: [] };
    const { result, rerender } = renderHook(({ s }: { s: LiveSession }) => useSecurityTimeline(s), {
      initialProps: { s: session1 },
    });
    const first = result.current;

    const session2: LiveSession = { ...BASE_SESSION, windows: [makeWindow(0, "NORMAL")] };
    rerender({ s: session2 });
    expect(result.current).not.toBe(first);
  });
});

