/**
 * Phase 5 — Incident History Table
 *
 * Lists all confirmed incidents from the active live session and stored analyses.
 * Filters by severity, attack type (Mode 1 / Mode 2), and status.
 * Each row opens the full IncidentReportModal.
 * "Export All (CSV)" downloads a CSV of the filtered list.
 */
import { useState, useMemo } from "react";
import {
  AlertCircle,
  AlertTriangle,
  ChevronRight,
  Clock,
  Download,
  FileText,
  Filter,
  ShieldAlert,
} from "lucide-react";

import { Button } from "@/components/ui/button";
import { fmtTime } from "@/components/app/primitives";
import { IncidentReportModal, exportIncidentCsv } from "@/components/app/IncidentReportModal";
import type { LiveIncident, ResponseLatency } from "@/lib/api/schemas";
import { cn } from "@/lib/utils";

// ─── Types ───────────────────────────────────────────────────────────────────

type SeverityFilter = "ALL" | "HIGH" | "MEDIUM" | "REVIEW";
type ModeFilter = "ALL" | 1 | 2;
type StatusFilter = "ALL" | "RECOVERED" | "VERIFYING" | "TERMINATED" | "REGISTERED";

export interface IncidentHistoryTableProps {
  /** Incidents from the live session (s.incidents). */
  liveIncidents: LiveIncident[];
  /** Incidents stored from past analyses (optional enriched with analysis_id). */
  historicIncidents?: LiveIncident[];
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

function modeLabelShort(mode: number | null | undefined): string {
  if (mode === 1) return "Mode 1 · Flood";
  if (mode === 2) return "Mode 2 · Ext ID";
  return "—";
}

function severityBadgeClass(sev: string) {
  if (sev === "HIGH") return "border-destructive/40 bg-destructive/10 text-destructive";
  if (sev === "MEDIUM") return "border-orange-500/40 bg-orange-500/10 text-orange-500";
  return "border-border bg-secondary text-muted-foreground";
}

function statusLabel(inc: LiveIncident): string {
  const rs = inc.response_state;
  if (!rs) return inc.status ?? "—";
  if (rs === "QUEUED") return "Queued";
  if (rs === "REGISTERED") {
    const rr = inc.response_result as Record<string, unknown> | undefined;
    const verif = rr?.["verification"] as Record<string, unknown> | undefined;
    const verified = (verif?.["recovery"] as Record<string, unknown> | undefined)?.["verified"];
    if (verified === true) return "RECOVERED";
    return "REGISTERED";
  }
  if (rs === "ERROR") return "Error";
  return rs;
}

function inferMode(inc: LiveIncident): number | null {
  const latency: ResponseLatency | undefined = inc.response_latency;
  if (latency?.attack_mode != null) return latency.attack_mode;
  return null;
}

/** Build a flattened CSV of all incidents in the filtered list. */
function exportAllCsv(incidents: LiveIncident[], filename: string): void {
  const header = [
    "Incident ID",
    "Analysis ID",
    "Severity",
    "Status",
    "Attack Mode",
    "Start Time UTC",
    "End Time UTC",
    "Window Count",
    "Affected CAN IDs",
    "Detection-to-Termination (ms)",
    "Response State",
  ];
  const rows: string[][] = [
    header,
    ...incidents.map((inc) => {
      const latency: ResponseLatency | undefined = inc.response_latency;
      return [
        inc.incident_id,
        inc.analysis_id ?? "",
        inc.severity,
        statusLabel(inc),
        String(latency?.attack_mode ?? ""),
        inc.start_time_utc,
        inc.end_time_utc,
        String(inc.window_count),
        (inc.affected_can_ids ?? []).join(" | "),
        String(latency?.detection_to_termination_ms ?? ""),
        inc.response_state ?? inc.status ?? "",
      ];
    }),
  ];
  const escaped = rows.map((row) =>
    row.map((cell) => `"${cell.replace(/"/g, '""')}"`).join(",")
  );
  const csv = escaped.join("\r\n");
  const blob = new Blob([csv], { type: "text/csv;charset=utf-8;" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

// ─── IncidentHistoryTable ─────────────────────────────────────────────────────

export function IncidentHistoryTable({
  liveIncidents,
  historicIncidents = [],
}: IncidentHistoryTableProps) {
  const [severityFilter, setSeverityFilter] = useState<SeverityFilter>("ALL");
  const [modeFilter, setModeFilter] = useState<ModeFilter>("ALL");
  const [statusFilter, setStatusFilter] = useState<StatusFilter>("ALL");
  const [reportIncident, setReportIncident] = useState<LiveIncident | null>(null);

  // Merge: live incidents shown first (newest session at top), historic below
  const all: LiveIncident[] = useMemo(() => {
    // De-duplicate by incident_id — live session always wins
    const liveIds = new Set(liveIncidents.map((i) => i.incident_id));
    const deduped = historicIncidents.filter((i) => !liveIds.has(i.incident_id));
    return [...liveIncidents, ...deduped];
  }, [liveIncidents, historicIncidents]);

  const filtered = useMemo(() => {
    return all.filter((inc) => {
      if (severityFilter !== "ALL" && inc.severity !== severityFilter) return false;
      if (modeFilter !== "ALL") {
        const mode = inferMode(inc);
        if (mode !== modeFilter) return false;
      }
      if (statusFilter !== "ALL") {
        const sl = statusLabel(inc);
        if (!sl.toUpperCase().includes(statusFilter)) return false;
      }
      return true;
    });
  }, [all, severityFilter, modeFilter, statusFilter]);

  if (all.length === 0) {
    return (
      <div className="rounded-lg border border-dashed p-6 text-center">
        <FileText className="mx-auto mb-2 size-6 text-muted-foreground" />
        <p className="text-sm font-medium text-muted-foreground">No confirmed incidents yet</p>
        <p className="mt-1 text-xs text-muted-foreground">
          Incidents are recorded only after the Isolation Forest confirms an anomaly cluster.
        </p>
      </div>
    );
  }

  return (
    <>
      {/* ── Filter bar ── */}
      <div className="mb-3 flex flex-wrap items-center gap-2">
        <span className="flex items-center gap-1 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
          <Filter className="size-3.5" />
          Filter:
        </span>

        {/* Severity */}
        <div className="flex gap-1">
          {([
            { label: "All Severities", v: "ALL" as SeverityFilter },
            { label: "HIGH", v: "HIGH" as SeverityFilter },
            { label: "MEDIUM", v: "MEDIUM" as SeverityFilter },
            { label: "REVIEW", v: "REVIEW" as SeverityFilter },
          ]).map(({ label, v }) => (
            <button
              key={v}
              type="button"
              onClick={() => setSeverityFilter(v)}
              className={cn(
                "rounded border px-2 py-0.5 text-[0.68rem] font-semibold transition-colors",
                severityFilter === v
                  ? "border-primary bg-primary text-primary-foreground"
                  : "border-border bg-secondary/60 text-muted-foreground hover:text-foreground"
              )}
            >
              {label}
            </button>
          ))}
        </div>

        <span className="text-muted-foreground/40 text-xs">|</span>

        {/* Mode */}
        <div className="flex gap-1">
          {([
            { label: "All Modes", v: "ALL" as ModeFilter },
            { label: "Mode 1 · Flood", v: 1 as ModeFilter },
            { label: "Mode 2 · Ext ID", v: 2 as ModeFilter },
          ]).map(({ label, v }) => (
            <button
              key={String(v)}
              type="button"
              onClick={() => setModeFilter(v)}
              className={cn(
                "rounded border px-2 py-0.5 text-[0.68rem] font-semibold transition-colors",
                modeFilter === v
                  ? "border-primary bg-primary text-primary-foreground"
                  : "border-border bg-secondary/60 text-muted-foreground hover:text-foreground"
              )}
            >
              {label}
            </button>
          ))}
        </div>

        <span className="text-muted-foreground/40 text-xs">|</span>

        {/* Status */}
        <div className="flex gap-1">
          {([
            { label: "All Statuses", v: "ALL" as StatusFilter },
            { label: "RECOVERED", v: "RECOVERED" as StatusFilter },
            { label: "REGISTERED", v: "REGISTERED" as StatusFilter },
            { label: "TERMINATED", v: "TERMINATED" as StatusFilter },
          ]).map(({ label, v }) => (
            <button
              key={v}
              type="button"
              onClick={() => setStatusFilter(v)}
              className={cn(
                "rounded border px-2 py-0.5 text-[0.68rem] font-semibold transition-colors",
                statusFilter === v
                  ? "border-primary bg-primary text-primary-foreground"
                  : "border-border bg-secondary/60 text-muted-foreground hover:text-foreground"
              )}
            >
              {label}
            </button>
          ))}
        </div>

        <div className="ml-auto">
          <Button
            variant="outline"
            size="sm"
            className="gap-1.5 text-xs"
            disabled={filtered.length === 0}
            onClick={() =>
              exportAllCsv(filtered, `incident_history_${Date.now()}.csv`)
            }
          >
            <Download className="size-3.5" />
            Export All ({filtered.length})
          </Button>
        </div>
      </div>

      {/* ── Table ── */}
      {filtered.length === 0 ? (
        <div className="rounded-lg border border-dashed p-4 text-center text-xs text-muted-foreground">
          No incidents match the current filters.
        </div>
      ) : (
        <div className="overflow-x-auto rounded-lg border border-border/60">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-border/60 bg-secondary/40">
                <Th>Incident ID</Th>
                <Th>Severity</Th>
                <Th>Mode</Th>
                <Th>Status</Th>
                <Th>Confirmed At</Th>
                <Th>Affected IDs</Th>
                <Th>Det→Term (ms)</Th>
                <Th className="text-right">Action</Th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((inc, idx) => {
                const latency: ResponseLatency | undefined = inc.response_latency;
                const dtms = latency?.detection_to_termination_ms;
                const sl = statusLabel(inc);
                const isRecovered = sl === "RECOVERED";
                const isLive = liveIncidents.some((l) => l.incident_id === inc.incident_id);
                return (
                  <tr
                    key={`${inc.incident_id}-${idx}`}
                    className="border-b border-border/40 transition-colors hover:bg-secondary/30"
                  >
                    <Td>
                      <div className="flex items-center gap-1.5">
                        {isLive && (
                          <span className="relative flex size-1.5 shrink-0">
                            <span className="absolute inline-flex size-full animate-ping rounded-full bg-destructive opacity-75" />
                            <span className="relative inline-flex size-1.5 rounded-full bg-destructive" />
                          </span>
                        )}
                        <span className="font-mono font-semibold text-foreground">
                          {inc.incident_id}
                        </span>
                      </div>
                    </Td>
                    <Td>
                      <span
                        className={cn(
                          "rounded border px-1.5 py-0.5 font-mono text-[0.65rem] font-bold",
                          severityBadgeClass(inc.severity)
                        )}
                      >
                        {inc.severity}
                      </span>
                    </Td>
                    <Td>
                      <span className="font-mono text-muted-foreground">
                        {modeLabelShort(latency?.attack_mode)}
                      </span>
                    </Td>
                    <Td>
                      <span
                        className={cn(
                          "font-mono",
                          isRecovered
                            ? "text-emerald-500"
                            : sl === "Error"
                              ? "text-destructive"
                              : "text-muted-foreground"
                        )}
                      >
                        {sl}
                      </span>
                    </Td>
                    <Td>
                      <span className="flex items-center gap-1 text-muted-foreground">
                        <Clock className="size-3 shrink-0" />
                        {latency?.incident_confirmed_utc
                          ? fmtTime(latency.incident_confirmed_utc)
                          : fmtTime(inc.start_time_utc)}
                      </span>
                    </Td>
                    <Td>
                      <div className="flex flex-wrap gap-0.5">
                        {(inc.affected_can_ids ?? []).slice(0, 3).map((id) => (
                          <span
                            key={id}
                            className="rounded border border-border/60 bg-secondary/60 px-1 py-0.5 font-mono text-[0.6rem]"
                          >
                            {id}
                          </span>
                        ))}
                        {(inc.affected_can_ids ?? []).length > 3 && (
                          <span className="text-muted-foreground">
                            +{(inc.affected_can_ids ?? []).length - 3}
                          </span>
                        )}
                      </div>
                    </Td>
                    <Td>
                      <span
                        className={cn(
                          "font-mono",
                          dtms != null && dtms < 5000
                            ? "text-emerald-500"
                            : dtms != null
                              ? "text-amber-500"
                              : "text-muted-foreground"
                        )}
                      >
                        {dtms != null ? dtms.toLocaleString() : "—"}
                      </span>
                    </Td>
                    <Td className="text-right">
                      <Button
                        variant="ghost"
                        size="sm"
                        className="h-6 gap-1 px-2 text-[0.68rem]"
                        onClick={() => setReportIncident(inc)}
                      >
                        View Report
                        <ChevronRight className="size-3" />
                      </Button>
                    </Td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      {/* Summary footer */}
      <div className="mt-2 flex items-center justify-between text-[0.68rem] text-muted-foreground">
        <span>
          {filtered.length} of {all.length} incident{all.length !== 1 ? "s" : ""} shown
        </span>
        <span className="flex items-center gap-1">
          <span className="relative flex size-1.5">
            <span className="absolute inline-flex size-full animate-ping rounded-full bg-destructive opacity-75" />
            <span className="relative inline-flex size-1.5 rounded-full bg-destructive" />
          </span>
          Live session incident
        </span>
      </div>

      {/* Full report modal */}
      <IncidentReportModal
        incident={reportIncident}
        isOpen={reportIncident !== null}
        onClose={() => setReportIncident(null)}
      />
    </>
  );
}

// ─── Table primitives ─────────────────────────────────────────────────────────

function Th({ children, className }: { children: React.ReactNode; className?: string }) {
  return (
    <th
      className={cn(
        "px-3 py-2 text-left text-[0.65rem] font-semibold uppercase tracking-wider text-muted-foreground",
        className
      )}
    >
      {children}
    </th>
  );
}

function Td({ children, className }: { children: React.ReactNode; className?: string }) {
  return <td className={cn("px-3 py-2.5", className)}>{children}</td>;
}

