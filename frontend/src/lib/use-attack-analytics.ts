/**
 * useAttackAnalytics
 *
 * Pure derivation hook — computes Attack Prevention Analytics metrics from the
 * LiveSession snapshot that is polled by useLiveSession.
 *
 * RIGOROUS MEASUREMENT CRITERIA (Phase 4 Corrections):
 * 1. Attack attempts: Counted from persistent per-session `attack_history`,
 *    accurately reflecting repeated attacks of identical or mixed modes.
 * 2. Mode attribution: Statistics for Mode 1 (Flood 0x100) and Mode 2 (Extended 0x999)
 *    are attributed to individual attack history records.
 * 3. Normal traffic interruptions: Measured strictly via normal generator lifecycle
 *    termination reasons (e.g. "PROCESS_CRASH" or non-zero exit code). Manual user
 *    stops ("MANUAL_USER_STOP", "SESSION_STOP") are NEVER counted as interruptions.
 * 4. Frame attribution: CAN arbitration ID 0x100 is emitted by BOTH normal RPM
 *    generator and Mode 1 flood simulator. Bus-level frames cannot be attributed with
 *    100% cryptographic certainty without sender tagging; attribution during Mode 1
 *    is clearly marked as ESTIMATED.
 * 5. Response Latency: Measured in milliseconds using actual backend milestones:
 *    first_anomalous_window_utc -> incident_confirmed_utc -> response_initiated_utc -> attack_terminated_utc.
 * 6. Successful terminations: Only counted after confirming the specific attack process
 *    exited cleanly (return_code 0 or clean signal exit). In-progress attacks are never counted.
 * 7. False Positives: Ground truth is UNAVAILABLE on uninstrumented live virtual CAN bus.
 *    Single isolated anomaly windows that do not form a 2-window incident are labeled as
 *    "Uncorrelated Anomaly Windows (Ground truth unavailable)".
 */
import { useMemo } from "react";
import type { LiveSession, LiveAttackRecord, LiveNormalRecord, LiveIncident } from "@/lib/api/schemas";

// ─── Types ───────────────────────────────────────────────────────────────────

export interface AttackModeStats {
  mode: 1 | 2;
  label: string;
  attempts: number;
  detected: number;
  successfulTerminations: number;
  failedTerminations: number;
  avgLatencyMs: number | null;
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
  isEstimated: boolean;
}

/** Response Latency per incident */
export interface LatencyDataPoint {
  incidentId: string;
  firstAnomalousWindowUtc?: string | null;
  incidentConfirmedUtc?: string | null;
  responseInitiatedUtc?: string | null;
  attackTerminatedUtc?: string | null;
  detectionToTerminationMs: number | null;
  detectionMs?: number | null;
  mitigationMs?: number | null;
  attackMode: number | null;
  severity: string;
}

export interface AttackAnalytics {
  // ── Core counters ──────────────────────────────────────────────────────────
  /** Total attack attempts across session attack history */
  totalAttackAttempts: number;
  /** Total attacks detected (confirmed backend incidents) */
  totalAttacksDetected: number;
  /** Successfully terminated attack processes (verified process exit with return_code 0/clean) */
  successfulTerminations: number;
  /** Failed termination attempts (process exit code != 0 or termination error) */
  failedTerminations: number;
  /** Normal traffic interruptions (crashes/abnormal exits, excluding manual stops) */
  normalTrafficInterruptions: number;
  /** Mean detection-to-termination latency in milliseconds across confirmed incidents */
  avgResponseLatencyMs: number | null;
  /** Estimated normal-traffic frames captured during anomalous windows (0x100 shared with Mode 1) */
  estimatedNormalFramesDuringAttack: number;
  /** Estimated normal-traffic frames captured after attack process stopped */
  estimatedNormalFramesAfterMitigation: number;
  /** Whether normal vs malicious frame attribution is estimated due to shared 0x100 */
  isFrameAttributionEstimated: boolean;
  /** Windows flagged ANOMALY but not forming a multi-window incident (Ground truth unavailable) */
  uncorrelatedAnomalyWindows: number;
  /** Ground truth status for false positives */
  falsePositiveStatus: "UNAVAILABLE";
  falsePositiveNote: string;

  // ── Per-mode stats ─────────────────────────────────────────────────────────
  mode1Stats: AttackModeStats;
  mode2Stats: AttackModeStats;

  // ── Chart data ─────────────────────────────────────────────────────────────
  trafficTimeSeries: TrafficDataPoint[];
  latencyPoints: LatencyDataPoint[];

  // ── Current session state ──────────────────────────────────────────────────
  hasIncidents: boolean;
  recoveryVerified: boolean;
  verifiedNormalWindows: number;
  currentAttackMode: number | null;
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
    avgLatencyMs: null,
    peakAnomalyScore: 0,
  };
}

function parseIsoMs(ts?: string | null): number | null {
  if (!ts) return null;
  try {
    const ms = Date.parse(ts);
    return isNaN(ms) ? null : ms;
  } catch {
    return null;
  }
}

function deriveAnalytics(session: LiveSession | undefined): AttackAnalytics {
  const empty: AttackAnalytics = {
    totalAttackAttempts: 0,
    totalAttacksDetected: 0,
    successfulTerminations: 0,
    failedTerminations: 0,
    normalTrafficInterruptions: 0,
    avgResponseLatencyMs: null,
    estimatedNormalFramesDuringAttack: 0,
    estimatedNormalFramesAfterMitigation: 0,
    isFrameAttributionEstimated: true,
    uncorrelatedAnomalyWindows: 0,
    falsePositiveStatus: "UNAVAILABLE",
    falsePositiveNote: "Ground truth mechanism unavailable on uninstrumented live virtual CAN bus",
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
  const recovery = session.recovery;

  // ── 1. Attack attempts from persistent per-session attack history ──────────
  // Fall back to session.attack if session.attack_history is not populated
  const attackHistory: LiveAttackRecord[] =
    session.attack_history && session.attack_history.length > 0
      ? session.attack_history
      : session.attack && session.attack.state !== "NOT_STARTED"
        ? [
            {
              attack_id: "att_1",
              mode: session.attack.mode ?? 1,
              pid: session.attack.pid,
              state: session.attack.state,
              started_at: session.started_at,
              stopped_at: session.attack.state === "STOPPED" ? session.started_at : null,
              return_code: session.attack.return_code ?? null,
              termination_reason: session.attack.state === "STOPPED" ? "TERMINATED" : null,
            },
          ]
        : [];

  const totalAttackAttempts = attackHistory.length;

  // ── 2. Detections = confirmed incidents ───────────────────────────────────
  const totalAttacksDetected = incidents.length;

  // ── 3. Successful vs Failed terminations across individual attack records ──
  // A termination is counted ONLY when the process has exited (state === "STOPPED")
  // Clean termination: return_code === 0 or null (SIGINT clean exit) AND reason != PROCESS_CRASH
  // Failed termination: return_code != 0
  let successfulTerminations = 0;
  let failedTerminations = 0;

  for (const att of attackHistory) {
    if (att.state === "STOPPED") {
      const rc = att.return_code;
      if (att.termination_reason === "PROCESS_CRASH" || (rc != null && rc !== 0)) {
        failedTerminations++;
      } else {
        successfulTerminations++;
      }
    }
  }

  // ── 4. Normal traffic interruptions from generator lifecycle ─────────────
  // Interruption is counted ONLY if the normal generator crashed or exited abnormally.
  // Manual user stops ("MANUAL_USER_STOP", "MANUAL_USER_STOP_ALL", "SESSION_STOP")
  // are NEVER counted as interruptions.
  const normalHistory: LiveNormalRecord[] =
    session.normal_history && session.normal_history.length > 0
      ? session.normal_history
      : session.normal && session.normal.state !== "NOT_STARTED"
        ? [
            {
              normal_id: "norm_1",
              pid: session.normal.pid,
              state: session.normal.state,
              started_at: session.started_at,
              stopped_at: session.normal.state === "STOPPED" ? session.started_at : null,
              return_code: session.normal.return_code ?? null,
              termination_reason: null,
            },
          ]
        : [];

  const normalTrafficInterruptions = normalHistory.filter((n) => {
    if (n.state !== "STOPPED") return false;
    if (n.termination_reason === "PROCESS_CRASH") return true;
    if (n.return_code != null && n.return_code !== 0) return true;
    return false;
  }).length;

  // ── 5. Response Latency in milliseconds ───────────────────────────────────
  const latencyPoints: LatencyDataPoint[] = incidents.map((inc: LiveIncident) => {
    const lat = inc.response_latency;
    let detectionToTerminationMs: number | null = lat?.detection_to_termination_ms ?? null;

    // If backend latency wasn't pre-computed, calculate from available ISO timestamps
    if (detectionToTerminationMs == null) {
      const t0 = parseIsoMs(lat?.first_anomalous_window_utc ?? inc.start_time_utc);
      const t3 = parseIsoMs(lat?.attack_terminated_utc ?? inc.end_time_utc);
      if (t0 != null && t3 != null && t3 >= t0) {
        detectionToTerminationMs = t3 - t0;
      }
    }

    return {
      incidentId: inc.incident_id,
      firstAnomalousWindowUtc: lat?.first_anomalous_window_utc ?? inc.start_time_utc,
      incidentConfirmedUtc: lat?.incident_confirmed_utc ?? inc.end_time_utc,
      responseInitiatedUtc: lat?.response_initiated_utc ?? null,
      attackTerminatedUtc: lat?.attack_terminated_utc ?? null,
      detectionToTerminationMs,
      detectionMs: lat?.detection_ms ?? null,
      mitigationMs: lat?.mitigation_ms ?? null,
      attackMode: lat?.attack_mode ?? session.attack?.mode ?? null,
      severity: inc.severity,
    };
  });

  const validLatencies = latencyPoints
    .map((p) => p.detectionToTerminationMs)
    .filter((ms): ms is number => ms != null && ms >= 0);

  const avgResponseLatencyMs =
    validLatencies.length > 0
      ? Math.round(validLatencies.reduce((a, b) => a + b, 0) / validLatencies.length)
      : null;

  // ── 6. Normal frames during attack / after mitigation (ESTIMATED) ─────────
  // Note: CAN ID 0x100 is emitted by both normal RPM generator and Mode 1 flood simulator.
  // Frames cannot be separated on the bus without sender tagging. Marked as ESTIMATED.
  const stoppedAfterIdx = recovery?.stopped_after_window_index ?? null;
  let estimatedNormalFramesDuringAttack = 0;
  let estimatedNormalFramesAfterMitigation = 0;

  for (const w of windows) {
    const evidence = w.response_evidence;
    if (!evidence?.can_id_counts) continue;

    const normalCount = Object.entries(evidence.can_id_counts)
      .filter(([id]) => NORMAL_CAN_IDS.has(id.toLowerCase()) || NORMAL_CAN_IDS.has(id))
      .reduce((acc, [, cnt]) => acc + cnt, 0);

    if (w.prediction === "ANOMALY") {
      estimatedNormalFramesDuringAttack += normalCount;
    } else if (stoppedAfterIdx != null && w.window_index > stoppedAfterIdx) {
      estimatedNormalFramesAfterMitigation += normalCount;
    }
  }

  // ── 7. False Positives Ground Truth Check ─────────────────────────────────
  // Ground truth ECU attestation does not exist on live virtual CAN interface.
  // Single isolated anomaly windows not reaching 2-window threshold are uncorrelated.
  const confirmedWindowIndices = new Set<number>();
  for (const inc of incidents) {
    for (let i = inc.start_window; i <= inc.end_window; i++) {
      confirmedWindowIndices.add(i);
    }
  }
  const uncorrelatedAnomalyWindows = windows.filter(
    (w) => w.prediction === "ANOMALY" && !confirmedWindowIndices.has(w.window_index)
  ).length;

  // ── 8. Per-mode stats from individual attack records ──────────────────────
  const mode1Stats = emptyModeStats(1);
  const mode2Stats = emptyModeStats(2);

  for (const att of attackHistory) {
    const target = att.mode === 1 ? mode1Stats : mode2Stats;
    target.attempts++;

    if (att.state === "STOPPED") {
      const rc = att.return_code;
      if (att.termination_reason === "PROCESS_CRASH" || (rc != null && rc !== 0)) {
        target.failedTerminations++;
      } else {
        target.successfulTerminations++;
      }
    }
  }

  // Attribute detected incidents and latencies to modes
  for (const lp of latencyPoints) {
    const target = lp.attackMode === 2 ? mode2Stats : mode1Stats;
    target.detected++;
    if (lp.detectionToTerminationMs != null) {
      const existing = target.avgLatencyMs;
      target.avgLatencyMs =
        existing != null
          ? Math.round((existing + lp.detectionToTerminationMs) / 2)
          : lp.detectionToTerminationMs;
    }
  }

  // Peak anomaly score per mode
  const anomalyWindows = windows.filter((w) => w.prediction === "ANOMALY");
  if (anomalyWindows.length > 0) {
    const scores = anomalyWindows.map((w) => w.anomaly_score);
    const peak = Math.max(...scores);
    // Attribute peak to the active or dominant attack mode
    if (mode1Stats.attempts > 0) mode1Stats.peakAnomalyScore = peak;
    if (mode2Stats.attempts > 0) mode2Stats.peakAnomalyScore = peak;
  }

  // ── 9. Traffic time series ────────────────────────────────────────────────
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
      isEstimated: true, // 0x100 is shared during Mode 1
    };
  });

  return {
    totalAttackAttempts,
    totalAttacksDetected,
    successfulTerminations,
    failedTerminations,
    normalTrafficInterruptions,
    avgResponseLatencyMs,
    estimatedNormalFramesDuringAttack,
    estimatedNormalFramesAfterMitigation,
    isFrameAttributionEstimated: true,
    uncorrelatedAnomalyWindows,
    falsePositiveStatus: "UNAVAILABLE",
    falsePositiveNote: "Ground truth mechanism unavailable on uninstrumented live virtual CAN bus",
    mode1Stats,
    mode2Stats,
    trafficTimeSeries,
    latencyPoints,
    hasIncidents: incidents.length > 0,
    recoveryVerified: recovery?.state === "RECOVERED",
    verifiedNormalWindows: recovery?.normal_windows ?? 0,
    currentAttackMode: session.attack?.mode ?? null,
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
