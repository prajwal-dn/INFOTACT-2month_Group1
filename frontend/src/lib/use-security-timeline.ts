/**
 * useSecurityTimeline
 *
 * Pure derivation hook — builds a deduplicated, chronologically-sorted list of
 * SecurityTimelineEvent objects from the LiveSession snapshot that is already
 * polled by useLiveSession.  No extra API calls are made.
 *
 * Event IDs are stable across polls so React never sees phantom duplicates.
 */
import { useMemo } from "react";
import type { LiveSession } from "@/lib/api/schemas";

// ─── Types ───────────────────────────────────────────────────────────────────

export type TimelineCategory =
  | "system"   // blue/cyan — session lifecycle events
  | "normal"   // green — normal traffic observations
  | "anomaly"  // amber — anomalous window detected
  | "incident" // red — confirmed security incident
  | "response" // red/amber — automated response actions
  | "recovery"; // green — recovery / verification

export type TimelineSeverity = "info" | "normal" | "warning" | "critical";

export interface TimelineEvent {
  /** Stable dedup key — never changes across polls for the same logical event. */
  id: string;
  /** ISO-8601 string from the backend (or session.started_at for session-level events). */
  timestamp: string;
  category: TimelineCategory;
  severity: TimelineSeverity;
  title: string;
  description: string;
  /** Relevant CAN IDs from the backend, if available. */
  can_ids?: string[];
  /** Linked incident ID, if available. */
  incident_id?: string;
  /** Anomaly score from the model, if available. */
  score?: number;
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

function topCanIds(counts: Record<string, number>, limit = 3): string[] {
  return Object.entries(counts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, limit)
    .map(([id]) => id);
}

// ─── Main derivation ─────────────────────────────────────────────────────────

function deriveEvents(session: LiveSession | undefined): TimelineEvent[] {
  if (!session) return [];

  const events: TimelineEvent[] = [];

  // ── 1. Monitoring started ────────────────────────────────────────────────
  events.push({
    id: `start:${session.id}`,
    timestamp: session.started_at,
    category: "system",
    severity: "info",
    title: "Live monitoring started",
    description: `Session ${session.id.slice(0, 8)} · interface ${session.interface}`,
  });

  // ── 2. Per-window events ─────────────────────────────────────────────────
  // Batch consecutive NORMAL windows into periodic summary events
  // (emit one entry per 5-window normal streak to avoid noise).
  // Emit every ANOMALY window individually.
  let normalStreak = 0;
  let streakStartIdx = 0;
  let streakStartTs = "";

  for (const w of session.windows) {
    if (w.prediction === "NORMAL") {
      if (normalStreak === 0) {
        streakStartIdx = w.window_index;
        streakStartTs = w.window_start_utc;
      }
      normalStreak++;

      // Emit a summary every 5 consecutive normal windows
      if (normalStreak % 5 === 0) {
        events.push({
          id: `normal-streak:${session.id}:${streakStartIdx}:${w.window_index}`,
          timestamp: w.window_start_utc,
          category: "normal",
          severity: "normal",
          title: "Normal CAN traffic observed",
          description: `${normalStreak} consecutive normal windows (w#${streakStartIdx}–w#${w.window_index})`,
        });
      }
    } else {
      // ANOMALY window
      normalStreak = 0;
      streakStartIdx = 0;
      streakStartTs = "";

      const canIds = w.response_evidence?.can_id_counts
        ? topCanIds(w.response_evidence.can_id_counts)
        : [];

      events.push({
        id: `anomaly:${session.id}:${w.window_index}`,
        timestamp: w.window_start_utc,
        category: "anomaly",
        severity: "warning",
        title: "Anomalous CAN traffic detected",
        description:
          `Window #${w.window_index} · score ${w.anomaly_score.toFixed(4)}` +
          (w.explanation?.summary ? ` · ${w.explanation.summary}` : ""),
        can_ids: canIds.length ? canIds : undefined,
        score: w.anomaly_score,
      });
    }
  }

  // ── 3. Incident + response events ────────────────────────────────────────
  for (const inc of session.incidents ?? []) {
    // 3a. Incident confirmed
    events.push({
      id: `incident:${inc.incident_id}`,
      timestamp: inc.start_time_utc,
      category: "incident",
      severity: inc.severity === "HIGH" ? "critical" : inc.severity === "MEDIUM" ? "warning" : "info",
      title: "Security incident confirmed",
      description:
        `${inc.severity} severity · ${inc.window_count} anomalous window${inc.window_count !== 1 ? "s" : ""}` +
        (inc.summary ? ` · ${inc.summary}` : ""),
      can_ids: inc.affected_can_ids.length ? inc.affected_can_ids : undefined,
      incident_id: inc.incident_id,
    });

    // 3b. Automated response initiated (when response_state moves past QUEUED)
    if (inc.response_state && inc.response_state !== "QUEUED") {
      // Best available timestamp is end_time_utc (when backend closed the incident window)
      events.push({
        id: `response-initiated:${inc.incident_id}`,
        timestamp: inc.end_time_utc,
        category: "response",
        severity: "warning",
        title: "Automated response initiated",
        description: `Response engine activated for incident ${inc.incident_id.slice(0, 8)} · state: ${inc.response_state}`,
        incident_id: inc.incident_id,
        can_ids: inc.affected_can_ids.length ? inc.affected_can_ids : undefined,
      });
    }

    // 3c. Response plan details if available
    const rr = inc.response_result as Record<string, unknown> | undefined;
    if (rr?.plan) {
      const plan = rr.plan as Record<string, unknown>;
      events.push({
        id: `response-plan:${inc.incident_id}`,
        timestamp: inc.end_time_utc,
        category: "response",
        severity: "warning",
        title: "Response plan generated",
        description: `Action: ${(plan.action as string) ?? "unknown"} · ${(plan.description as string) ?? ""}`,
        incident_id: inc.incident_id,
        can_ids:
          Array.isArray(plan.target_can_ids) && (plan.target_can_ids as string[]).length
            ? (plan.target_can_ids as string[])
            : undefined,
      });
    }
  }

  // ── 4. Generator & simulator events ──────────────────────────────────────
  const normal = session.normal;
  const attack = session.attack;
  const recovery = session.recovery;

  if (normal && normal.state !== "NOT_STARTED") {
    if (normal.state === "RUNNING") {
      events.push({
        id: `normal-running:${session.id}`,
        timestamp: session.started_at,
        category: "system",
        severity: "normal",
        title: "Normal CAN traffic generator running",
        description: `Legitimate powertrain traffic active (RPM 0x100, Speed 0x101, Coolant 0x102) · PID ${normal.pid ?? "—"}`,
        can_ids: ["0x100", "0x101", "0x102"],
      });
    } else if (normal.state === "STOPPED") {
      events.push({
        id: `normal-stopped:${session.id}`,
        timestamp: session.started_at,
        category: "system",
        severity: "info",
        title: "Normal CAN traffic generator stopped",
        description: `Legitimate traffic simulation stopped · return code ${normal.return_code ?? 0}`,
      });
    }
  }

  if (normal?.state === "RUNNING" && attack?.state === "RUNNING") {
    events.push({
      id: `concurrent-simulation:${session.id}`,
      timestamp: session.started_at,
      category: "system",
      severity: "warning",
      title: "Concurrent traffic simulation active",
      description: `Normal powertrain messages flowing simultaneously with Attack Mode ${attack.mode ?? 1}`,
      can_ids: attack.mode === 1 ? ["0x100", "0x101", "0x102"] : ["0x100", "0x101", "0x102", "0x999"],
    });
  }

  if (attack && attack.state !== "NOT_STARTED") {
    // Derive a timestamp from the window at stopped_after_window_index (if available)
    const stoppedIdx = recovery?.stopped_after_window_index ?? null;
    const stoppedWindow =
      stoppedIdx != null ? session.windows.find((w) => w.window_index === stoppedIdx) : null;
    const stoppedTs = stoppedWindow?.window_start_utc ?? null;

    // 4a. Termination attempted — emit when state is STOPPED or recovery is active
    if (attack.state === "STOPPED" || recovery?.state === "ATTACK_STOPPED_VERIFYING" || recovery?.state === "RECOVERED") {
      const ts = stoppedTs ?? session.started_at;
      events.push({
        id: `attack-terminate-attempt:${session.id}`,
        timestamp: ts,
        category: "response",
        severity: "warning",
        title: "Attack simulator termination attempted",
        description:
          "Automated response engine signalled the attack simulator to stop" +
          (stoppedIdx != null ? ` after window #${stoppedIdx}` : ""),
      });

      // 4b. Termination result
      const success = attack.return_code === 0 || attack.return_code == null;
      events.push({
        id: `attack-stopped:${session.id}`,
        timestamp: ts,
        category: "response",
        severity: success ? "warning" : "critical",
        title: success ? "Attack simulator terminated" : "Attack simulator termination failed",
        description: success
          ? `Malicious simulator process stopped · return code ${attack.return_code ?? "—"}`
          : `Termination failed · return code ${attack.return_code}`,
      });
    }
  }

  // ── 5. Recovery events ───────────────────────────────────────────────────
  if (recovery) {
    const stoppedIdx = recovery.stopped_after_window_index ?? null;

    // 5a. Recovery verification started
    if (
      recovery.state === "ATTACK_STOPPED_VERIFYING" ||
      recovery.state === "RECOVERED"
    ) {
      // Use the window right after stopping, if available
      const verifyWindow =
        stoppedIdx != null
          ? session.windows.find((w) => w.window_index === (stoppedIdx as number) + 1)
          : null;
      const verifyTs = verifyWindow?.window_start_utc ?? session.started_at;

      events.push({
        id: `recovery-started:${session.id}`,
        timestamp: verifyTs,
        category: "recovery",
        severity: "warning",
        title: "Recovery verification started",
        description: `Waiting for ${recovery.required_normal_windows ?? 2} consecutive normal windows · ${recovery.normal_windows ?? 0} observed so far`,
      });
    }

    // 5b. Normal traffic continuity (emit one event per normal window post-incident, capped)
    // Only emit when there's a previous incident to anchor against
    const hasIncident = (session.incidents?.length ?? 0) > 0;
    if (hasIncident && stoppedIdx != null) {
      const postStopNormalWindows = session.windows.filter(
        (w) => w.window_index > (stoppedIdx as number) && w.prediction === "NORMAL"
      );
      // Emit a single "continuity observed" event per 2 normal windows post-stop
      for (let i = 1; i < postStopNormalWindows.length; i += 2) {
        const w = postStopNormalWindows[i];
        events.push({
          id: `continuity:${session.id}:${w.window_index}`,
          timestamp: w.window_start_utc,
          category: "recovery",
          severity: "normal",
          title: "Normal traffic continuity observed",
          description: `Window #${w.window_index} normal after simulator stopped · ${i + 1} of ${recovery.required_normal_windows ?? 2} required`,
        });
      }
    }

    // 5c. Recovery verified
    if (recovery.state === "RECOVERED") {
      // Last window in the session is best available timestamp
      const lastWindow = session.windows[session.windows.length - 1];
      const recoveredTs = lastWindow?.window_start_utc ?? session.started_at;

      events.push({
        id: `recovered:${session.id}`,
        timestamp: recoveredTs,
        category: "recovery",
        severity: "normal",
        title: "Recovery verified",
        description: `${recovery.normal_windows ?? recovery.required_normal_windows ?? 2} consecutive normal windows confirmed · CAN bus traffic within baseline`,
      });
    }
  }

  // ── Sort: oldest first (ascending), then reverse for display ────────────
  events.sort((a, b) => a.timestamp.localeCompare(b.timestamp));

  return events;
}

// ─── Hook ────────────────────────────────────────────────────────────────────

/**
 * Derives a stable, deduplicated list of SecurityTimelineEvents from the
 * current LiveSession snapshot.  The returned array is memoised — referential
 * equality is preserved when the session object hasn't changed.
 */
export function useSecurityTimeline(session: LiveSession | undefined): TimelineEvent[] {
  return useMemo(() => deriveEvents(session), [session]);
}

// Also export the pure function for unit-testing without React
export { deriveEvents };

