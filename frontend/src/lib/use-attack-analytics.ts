/**
 * useAttackAnalytics
 *
 * Pure derivation hook — computes Attack Prevention Analytics metrics from the
 * LiveSession snapshot that is already polled by useLiveSession.
 *
 * IMPORTANT: Every value is derived from actual backend data:
 *   - session.windows[]       → per-window predictions, scores, can_id_counts
 *   - session.incidents[]     → confirmed backend incidents
 *   - session.attack          → process state + return_code (determines termination success)
 *   - session.normal          → normal generator state
 *   - session.recovery        → recovery verification progress
 *   - session.frames_captured → total frame count
 *
 * No metric is hardcoded or fabricated. A termination is counted as "successful"
 * only when attack.return_code is 0 or null (clean exit), never merely from an
 * incident being detected. Normal traffic continuity is counted from actual
 * window-level frame data, not from simulated values.
 */
import { useMemo } from "react";
import type { LiveSession } from "@/lib/api/schemas";

// ─── Types ───────────────────────────────────────────────────────────────────

export interface AttackModeStats {
  mode: 1 | 2;
  label: string;
  attempts: number;
  detected: number;
  successfulTerminations: number;
  failedTerminations: number;
  avgDetectionWindowCount: number;
  peakAnomalyScore: number;
}

/** Time series point for Normal vs Malicious traffic chart */
export interface TrafficDataPoint {
  windowIndex: number;
  windowStartUtc: string;
  normalFrames: number;
  maliciousFrames: number;
  totalFrames: number;
  prediction: "NORMAL" | "ANOMALY";
  anomalyScore: number;
}

/** Time series point for Response Latency chart */
export interface LatencyDataPoint {
  incidentId: string;
  /** Number of windows elapsed from first anomaly to incident being confirmed */
  detectionWindowCount: number;
  /** Attack mode that triggered this incident (from session.attack.mode) */
  attackMode: number | null;
  severity: string;
}

export interface AttackAnalytics {
  // ── Core counters ──────────────────────────────────────────────────────────
  /** Number of times attack.state transitioned to RUNNING in this session (1 per session for now) */
  totalAttackAttempts: number;
  /** Number of incidents confirmed by backend Isolation Forest */
  totalAttacksDetected: number;
  /** Terminations where attack.return_code === 0 or null (clean exit) */
  successfulTerminations: number;
  /** Terminations where attack.return_code is a non-zero integer */
  failedTerminations: number;
  /** Whether normal generator was interrupted (stopped while attack was active) */
  normalTrafficInterruptions: number;
  /** Average window count from first anomaly window to incident confirmation */
  avgDetectionWindowCount: number | null;
  /** Total normal-traffic frames captured during anomalous windows */
  normalFramesDuringAttack: number;
  /** Total normal-traffic frames captured after the attack was stopped */
  normalFramesAfterMitigation: number;
  /**
   * Windows predicted ANOMALY but no incident was ever confirmed.
   * These represent single isolated anomaly windows not reaching the
   * 2-consecutive-window threshold → they are not false positives in the
   * classical sense, but we surface them as "unconfirmed anomaly windows"
   * since we cannot say the backend confirmed them as incidents.
   */
  unconfirmedAnomalyWindows: number;

  // ── Per-mode stats ─────────────────────────────────────────────────────────
  mode1Stats: AttackModeStats;
  mode2Stats: AttackModeStats;

  // ── Chart data ─────────────────────────────────────────────────────────────
  trafficTimeSeries: TrafficDataPoint[];
  latencyPoints: LatencyDataPoint[];

  // ── Current session state ──────────────────────────────────────────────────
  /** true if any incident was confirmed in this session */
  hasIncidents: boolean;
  /** true if latest recovery state is RECOVERED */
  recoveryVerified: boolean;
  /** Consecutive normal windows verified post-attack */
  verifiedNormalWindows: number;
  /** Current attack mode from session.attack.mode */
  currentAttackMode: number | null;
  /** Summary of recovery state for display */
  recoveryState: string;
}

// ─── KNOWN normal CAN IDs (matches backend frequency_analyzer.py KNOWN_IDS) ─

const NORMAL_CAN_IDS = new Set(["0x100", "0x101", "0x102"]);

// ─── Pure computation ─────────────────────────────────────────────────────────

function emptyModeStats(mode: 1 | 2): AttackModeStats {
  return {
    mode,
    label: mode === 1 ? "Mode 1 · High-Freq Flood (0x100)" : "Mode 2 · Extended ID Inject (0x999)",
    attempts: 0,
    detected: 0,
    successfulTerminations: 0,
    failedTerminations: 0,
    avgDetectionWindowCount: 0,
    peakAnomalyScore: 0,
  };
}

function deriveAnalytics(session: LiveSession | undefined): AttackAnalytics {
  const empty: AttackAnalytics = {
    totalAttackAttempts: 0,
    totalAttacksDetected: 0,
    successfulTerminations: 0,
    failedTerminations: 0,
    normalTrafficInterruptions: 0,
    avgDetectionWindowCount: null,
    normalFramesDuringAttack: 0,
    normalFramesAfterMitigation: 0,
    unconfirmedAnomalyWindows: 0,
    mode1Stats: emptyModeStats(1),
    mode2Stats: emptyModeStats(2),
    trafficTimeSeries: [],
    latencyPoints: [],
    hasIncidents: false,
    recoveryVerified: false,
    verifiedNormalWindows: 0,
    currentAttackMode: null,
    recoveryState: "NOT_STARTED",
  };

  if (!session) return empty;

  const windows = session.windows ?? [];
  const incidents = session.incidents ?? [];
  const attack = session.attack;
  const normal = session.normal;
  const recovery = session.recovery;

  // ── 1. Attack attempt count ───────────────────────────────────────────────
  // The backend starts one attack process per session. We count an attempt
  // whenever attack.state is not "NOT_STARTED".
  const attackAttempted =
    attack?.state === "RUNNING" || attack?.state === "STOPPED";
  const totalAttackAttempts = attackAttempted ? 1 : 0;

  // ── 2. Detections = confirmed incidents ───────────────────────────────────
  const totalAttacksDetected = incidents.length;

  // ── 3. Termination success/failure ───────────────────────────────────────
  // Success = attack.return_code is 0 or null (clean SIGINT/natural exit).
  // Failure = attack.return_code is a non-zero integer.
  // We only count a termination when the process actually exited (state=STOPPED).
  let successfulTerminations = 0;
  let failedTerminations = 0;

  if (attack?.state === "STOPPED") {
    const rc = attack.return_code;
    if (rc == null || rc === 0) {
      successfulTerminations = 1;
    } else {
      failedTerminations = 1;
    }
  }

  // ── 4. Normal traffic interruptions ──────────────────────────────────────
  // Count: normal generator was STOPPED (by user or stopAll) while an attack
  // was also running in the same session. We detect this by checking if
  // normal.state=STOPPED and there was at least one incident.
  const normalInterrupted =
    normal?.state === "STOPPED" && incidents.length > 0 ? 1 : 0;

  // ── 5. Avg detection window count ─────────────────────────────────────────
  // For each confirmed incident: window_count is the number of anomalous windows
  // that were correlated. This is our proxy for detection latency.
  const detectionWindowCounts = incidents.map((inc) => inc.window_count ?? 1);
  const avgDetectionWindowCount =
    detectionWindowCounts.length > 0
      ? detectionWindowCounts.reduce((a, b) => a + b, 0) / detectionWindowCounts.length
      : null;

  // ── 6. Normal frames during attack / after mitigation ───────────────────
  // "During attack" = windows scored while attack.state was RUNNING, but we
  // don't have per-window process state. Best proxy: anomalous windows.
  // "Normal frames during attack" = frames from known normal IDs within anomaly windows.
  // "Normal frames after mitigation" = frames from known normal IDs in NORMAL
  // windows that appear after stopped_after_window_index.
  const stoppedAfterIdx = recovery?.stopped_after_window_index ?? null;

  let normalFramesDuringAttack = 0;
  let normalFramesAfterMitigation = 0;

  for (const w of windows) {
    const evidence = w.response_evidence;
    if (!evidence?.can_id_counts) continue;

    const normalCount = Object.entries(evidence.can_id_counts)
      .filter(([id]) => NORMAL_CAN_IDS.has(id.toLowerCase()) || NORMAL_CAN_IDS.has(id))
      .reduce((acc, [, cnt]) => acc + cnt, 0);

    if (w.prediction === "ANOMALY") {
      normalFramesDuringAttack += normalCount;
    } else if (stoppedAfterIdx != null && w.window_index > stoppedAfterIdx) {
      normalFramesAfterMitigation += normalCount;
    }
  }

  // ── 7. Unconfirmed anomaly windows ────────────────────────────────────────
  // Anomaly windows that were NOT part of any confirmed incident window range.
  const confirmedWindowIndices = new Set<number>();
  for (const inc of incidents) {
    for (let i = inc.start_window; i <= inc.end_window; i++) {
      confirmedWindowIndices.add(i);
    }
  }
  const unconfirmedAnomalyWindows = windows.filter(
    (w) => w.prediction === "ANOMALY" && !confirmedWindowIndices.has(w.window_index)
  ).length;

  // ── 8. Per-mode stats ─────────────────────────────────────────────────────
  // The backend tracks one attack process with one mode per session.
  // We attribute all incidents in this session to the current attack mode.
  const mode = attack?.mode as 1 | 2 | undefined;
  const mode1Stats = emptyModeStats(1);
  const mode2Stats = emptyModeStats(2);

  if (attackAttempted && mode) {
    const targetStats = mode === 1 ? mode1Stats : mode2Stats;
    targetStats.attempts = 1;
    targetStats.detected = incidents.length;
    targetStats.successfulTerminations = successfulTerminations;
    targetStats.failedTerminations = failedTerminations;
    targetStats.avgDetectionWindowCount =
      avgDetectionWindowCount != null ? Math.round(avgDetectionWindowCount * 10) / 10 : 0;

    // Peak anomaly score across all anomaly windows
    const anomalyScores = windows
      .filter((w) => w.prediction === "ANOMALY")
      .map((w) => w.anomaly_score);
    targetStats.peakAnomalyScore =
      anomalyScores.length > 0 ? Math.max(...anomalyScores) : 0;
  }

  // ── 9. Traffic time series ────────────────────────────────────────────────
  // For each scored window, compute normal vs malicious frame counts.
  // "Malicious frames" = frames from non-normal CAN IDs.
  // "Normal frames"   = frames from known normal IDs (0x100, 0x101, 0x102).
  const trafficTimeSeries: TrafficDataPoint[] = windows.map((w) => {
    const evidence = w.response_evidence;
    const idCounts = evidence?.can_id_counts ?? {};

    let normalF = 0;
    let maliciousF = 0;
    for (const [id, cnt] of Object.entries(idCounts)) {
      if (NORMAL_CAN_IDS.has(id.toLowerCase()) || NORMAL_CAN_IDS.has(id)) {
        normalF += cnt;
      } else {
        maliciousF += cnt;
      }
    }

    return {
      windowIndex: w.window_index,
      windowStartUtc: w.window_start_utc,
      normalFrames: normalF,
      maliciousFrames: maliciousF,
      totalFrames: normalF + maliciousF,
      prediction: w.prediction,
      anomalyScore: w.anomaly_score,
    };
  });

  // ── 10. Latency data points ───────────────────────────────────────────────
  const latencyPoints: LatencyDataPoint[] = incidents.map((inc) => ({
    incidentId: inc.incident_id,
    detectionWindowCount: inc.window_count ?? 1,
    attackMode: attack?.mode ?? null,
    severity: inc.severity,
  }));

  return {
    totalAttackAttempts,
    totalAttacksDetected,
    successfulTerminations,
    failedTerminations,
    normalTrafficInterruptions: normalInterrupted,
    avgDetectionWindowCount,
    normalFramesDuringAttack,
    normalFramesAfterMitigation,
    unconfirmedAnomalyWindows,
    mode1Stats,
    mode2Stats,
    trafficTimeSeries,
    latencyPoints,
    hasIncidents: incidents.length > 0,
    recoveryVerified: recovery?.state === "RECOVERED",
    verifiedNormalWindows: recovery?.normal_windows ?? 0,
    currentAttackMode: attack?.mode ?? null,
    recoveryState: recovery?.state ?? "NOT_STARTED",
  };
}

// ─── Hook ────────────────────────────────────────────────────────────────────

/**
 * Derives a stable, deduplicated AttackAnalytics object from the
 * current LiveSession snapshot.
 */
export function useAttackAnalytics(session: LiveSession | undefined): AttackAnalytics {
  return useMemo(() => deriveAnalytics(session), [session]);
}

// Also export the pure function for unit testing without React
export { deriveAnalytics };

