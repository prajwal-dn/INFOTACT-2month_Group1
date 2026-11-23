/**
 * Phase 5 — Detailed Incident Report Modal
 *
 * Displays a comprehensive SOC Investigation Report for one confirmed incident.
 * Data comes exclusively from actual backend incident fields.
 * Never fabricates timestamps, scores, PID, or mitigation results.
 */
import { useState } from "react";
import {
  AlertCircle,
  AlertTriangle,
  CheckCircle2,
  ChevronDown,
  ChevronUp,
  Clock,
  ClipboardList,
  Download,
  FileText,
  Info,
  Printer,
  ShieldAlert,
  ShieldCheck,
  XCircle,
} from "lucide-react";

import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { fmtTime } from "@/components/app/primitives";
import { getAttackClassification } from "@/components/app/SecurityAlertModal";
import type { LiveIncident, ResponseLatency } from "@/lib/api/schemas";
import { cn } from "@/lib/utils";

// ─── Types ───────────────────────────────────────────────────────────────────

interface IncidentReportModalProps {
  incident: LiveIncident | null;
  isOpen: boolean;
  onClose: () => void;
}

type SeverityLevel = "HIGH" | "MEDIUM" | "REVIEW";

// ─── Helpers ─────────────────────────────────────────────────────────────────

function fmtMs(ms: number | null | undefined): string {
  if (ms == null) return "—";
  if (ms < 1000) return `${ms} ms`;
  return `${(ms / 1000).toFixed(2)} s`;
}

function fmtTs(ts: string | null | undefined): string {
  if (!ts) return "—";
  return fmtTime(ts);
}

function severityColor(sev: SeverityLevel) {
  if (sev === "HIGH") return "text-destructive";
  if (sev === "MEDIUM") return "text-orange-500";
  return "text-muted-foreground";
}

function severityBadgeClass(sev: SeverityLevel) {
  if (sev === "HIGH") return "border-destructive/40 bg-destructive/10 text-destructive";
  if (sev === "MEDIUM") return "border-orange-500/40 bg-orange-500/10 text-orange-500";
  return "border-border bg-secondary text-muted-foreground";
}

function modeLabel(mode: number | null | undefined): string {
  if (mode === 1) return "Mode 1 — High-Frequency Flood (0x100)";
  if (mode === 2) return "Mode 2 — Unauthorized Extended ID Injection (0x999)";
  return "—";
}

/** Export a single incident as CSV. Never call this with fabricated data. */
export function exportIncidentCsv(incident: LiveIncident): void {
  const responseResult = incident.response_result as Record<string, unknown> | undefined;
  const attackRecord = responseResult?.["attack_record"] as Record<string, unknown> | undefined;
  const latency: ResponseLatency | undefined = incident.response_latency;

  const rows: string[][] = [
    ["Field", "Value"],
    ["Incident ID", incident.incident_id],
    ["Severity", incident.severity],
    ["Status", incident.status],
    ["Analysis ID", incident.analysis_id ?? ""],
    ["Attack Mode", String(latency?.attack_mode ?? "")],
    ["Start Window", String(incident.start_window)],
    ["End Window", String(incident.end_window)],
    ["Window Count", String(incident.window_count)],
    ["Start Time UTC", incident.start_time_utc],
    ["End Time UTC", incident.end_time_utc],
    ["Affected CAN IDs", (incident.affected_can_ids ?? []).join(" | ")],
    ["Evidence Summary", incident.summary],
    ["Detection Reasons", (incident.reasons ?? []).map((r) => `${r.code}: ${r.message}`).join(" | ")],
    // Response latency
    ["First Anomalous Window UTC", latency?.first_anomalous_window_utc ?? ""],
    ["Incident Confirmed UTC", latency?.incident_confirmed_utc ?? ""],
    ["Response Initiated UTC", latency?.response_initiated_utc ?? ""],
    ["Attack Terminated UTC", latency?.attack_terminated_utc ?? ""],
    ["Detection Latency (ms)", String(latency?.detection_ms ?? "")],
    ["Mitigation Latency (ms)", String(latency?.mitigation_ms ?? "")],
    ["Detection-to-Termination (ms)", String(latency?.detection_to_termination_ms ?? "")],
    // Response result
    ["Response State", incident.response_state ?? ""],
    ["Analysis Registered", String(incident.analysis_registered ?? "")],
    // Attack process details
    ["Attack PID", String(attackRecord?.["pid"] ?? responseResult?.["pid"] ?? "")],
    [
      "Process Return Code",
      String(attackRecord?.["return_code"] ?? responseResult?.["return_code"] ?? ""),
    ],
    [
      "Termination Reason",
      String(attackRecord?.["termination_reason"] ?? responseResult?.["termination_reason"] ?? ""),
    ],
    // Response evidence
    ["Dominant CAN ID", incident.response_evidence?.dominant_can_id ?? ""],
    ["Dominant ID Share %", String(incident.response_evidence?.dominant_can_id_share_pct ?? "")],
    ["Unexpected CAN IDs", (incident.response_evidence?.unexpected_can_ids ?? []).join(" | ")],
  ];

  const escaped = rows.map((row) =>
    row.map((cell) => `"${cell.replace(/"/g, '""')}"`).join(",")
  );
  const csv = escaped.join("\r\n");
  const blob = new Blob([csv], { type: "text/csv;charset=utf-8;" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `incident_${incident.incident_id}_report.csv`;
  a.click();
  URL.revokeObjectURL(url);
}

// ─── IncidentReportModal ─────────────────────────────────────────────────────

export function IncidentReportModal({ incident, isOpen, onClose }: IncidentReportModalProps) {
  const [showRawWindows, setShowRawWindows] = useState(false);

  if (!incident) return null;

  const attackInfo = getAttackClassification(incident);
  const severity = incident.severity;
  const latency: ResponseLatency | undefined = incident.response_latency;
  const responseResult = incident.response_result as Record<string, unknown> | undefined;
  // Try to find attack process metadata from multiple possible locations
  const attackRecord = responseResult?.["attack_record"] as Record<string, unknown> | undefined;
  const pid =
    attackRecord?.["pid"] ??
    responseResult?.["pid"] ??
    null;
  const returnCode =
    attackRecord?.["return_code"] ??
    responseResult?.["return_code"] ??
    null;
  const terminationReason =
    attackRecord?.["termination_reason"] ??
    responseResult?.["termination_reason"] ??
    null;

  const terminationSuccess = returnCode === 0;

  const scores = (incident.windows ?? []).map((w) => w.anomaly_score);
  const peakScore = scores.length > 0 ? Math.max(...scores) : null;
  const avgScore =
    scores.length > 0 ? scores.reduce((a, b) => a + b, 0) / scores.length : null;

  const recoveryVerification = responseResult?.["verification"] as
    | Record<string, unknown>
    | undefined;
  const recoveryVerified =
    (recoveryVerification?.["recovery"] as Record<string, unknown> | undefined)?.["verified"] ===
    true;

  return (
    <Dialog open={isOpen} onOpenChange={(open) => !open && onClose()}>
      <DialogContent
        className="max-h-[94vh] max-w-4xl overflow-y-auto bg-background/97 shadow-2xl backdrop-blur-md sm:rounded-xl print:max-h-none print:overflow-visible print:shadow-none"
        style={{ scrollbarGutter: "stable" }}
      >
        {/* ── Print-only letterhead ── */}
        <div className="mb-2 hidden print:block">
          <div className="flex items-center justify-between border-b pb-2">
            <div>
              <p className="text-xs font-bold uppercase tracking-wider text-muted-foreground">
                CAN-Sentinel · SOC Investigation Report
              </p>
              <p className="text-[0.68rem] text-muted-foreground">
                Generated {new Date().toUTCString()}
              </p>
            </div>
            <div className="font-mono text-sm font-semibold text-foreground">
              {incident.incident_id}
            </div>
          </div>
        </div>

        <DialogHeader className="space-y-1 border-b border-border/60 pb-4 text-left">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div className="flex items-center gap-2">
              <span className="relative flex size-3 print:hidden">
                <span className="absolute inline-flex size-full animate-ping rounded-full bg-destructive opacity-75" />
                <span className="relative inline-flex size-3 rounded-full bg-destructive" />
              </span>
              <span className="font-mono text-xs font-bold uppercase tracking-wider text-destructive">
                SOC Investigation Report
              </span>
            </div>
            <div className="flex items-center gap-1.5 print:hidden">
              <span
                className={cn(
                  "rounded-md border px-2.5 py-0.5 font-mono text-xs font-bold",
                  severityBadgeClass(severity)
                )}
              >
                {severity}
              </span>
              <span className="rounded-md border bg-secondary/80 px-2 py-0.5 font-mono text-xs font-semibold text-foreground">
                {incident.incident_id}
              </span>
            </div>
          </div>
          <DialogTitle className={cn("font-display text-xl font-bold tracking-tight", severityColor(severity))}>
            {severity === "HIGH" && <ShieldAlert className="mr-2 inline size-5 shrink-0" />}
            {severity === "MEDIUM" && <AlertTriangle className="mr-2 inline size-5 shrink-0" />}
            {severity === "REVIEW" && <AlertCircle className="mr-2 inline size-5 shrink-0" />}
            {attackInfo.category}
          </DialogTitle>
          <p className="text-xs text-muted-foreground">{attackInfo.description}</p>
        </DialogHeader>

        {/* ── Report body ── */}
        <div className="space-y-5 py-2">
          {/* Section 1 — Incident metadata */}
          <ReportSection title="Incident Identification" icon={<ClipboardList className="size-4" />}>
            <TwoColGrid>
              <Field label="Incident ID" value={incident.incident_id} mono />
              <Field label="Analysis ID" value={incident.analysis_id ?? "—"} mono />
              <Field label="Severity" value={severity} mono className={severityColor(severity)} />
              <Field
                label="Attack Mode"
                value={modeLabel(latency?.attack_mode)}
              />
              <Field label="Status" value={incident.status} mono />
              <Field
                label="Analysis Registered"
                value={
                  incident.analysis_registered === true
                    ? "Yes"
                    : incident.analysis_registered === false
                      ? "No (queued)"
                      : "—"
                }
              />
            </TwoColGrid>
          </ReportSection>

          {/* Section 2 — Detection timestamps */}
          <ReportSection title="Detection Timeline" icon={<Clock className="size-4" />}>
            <TwoColGrid>
              <Field label="First Anomalous Window" value={fmtTs(latency?.first_anomalous_window_utc)} />
              <Field label="Incident Confirmed" value={fmtTs(latency?.incident_confirmed_utc)} />
              <Field label="Response Initiated" value={fmtTs(latency?.response_initiated_utc)} />
              <Field label="Attack Process Terminated" value={fmtTs(latency?.attack_terminated_utc)} />
            </TwoColGrid>
            <TwoColGrid className="mt-2">
              <Field
                label="Detection Latency (anomaly → confirmed)"
                value={fmtMs(latency?.detection_ms)}
                mono
              />
              <Field
                label="Mitigation Latency (response → terminated)"
                value={fmtMs(latency?.mitigation_ms)}
                mono
              />
              <Field
                label="Detection-to-Termination"
                value={fmtMs(latency?.detection_to_termination_ms)}
                mono
                className="col-span-2"
              />
            </TwoColGrid>
          </ReportSection>

          {/* Section 3 — Traffic evidence */}
          <ReportSection title="Traffic Evidence" icon={<ShieldAlert className="size-4" />}>
            <TwoColGrid>
              <Field label="Anomalous Window Span" value={`#${incident.start_window} – #${incident.end_window}`} mono />
              <Field label="Anomalous Window Count" value={String(incident.window_count)} mono />
              <Field label="Incident Start UTC" value={fmtTs(incident.start_time_utc)} />
              <Field label="Incident End UTC" value={fmtTs(incident.end_time_utc)} />
            </TwoColGrid>

            {/* Affected CAN IDs */}
            <div className="mt-3">
              <p className="mb-1 text-[0.7rem] font-semibold uppercase tracking-wider text-muted-foreground">
                Suspicious CAN IDs
              </p>
              <div className="flex flex-wrap gap-1.5">
                {(incident.affected_can_ids ?? []).length > 0 ? (
                  (incident.affected_can_ids ?? []).map((id) => (
                    <span
                      key={id}
                      className="rounded border border-destructive/30 bg-destructive/10 px-2 py-0.5 font-mono text-xs text-destructive"
                    >
                      {id}
                    </span>
                  ))
                ) : (
                  <span className="text-xs text-muted-foreground">—</span>
                )}
              </div>
            </div>

            {/* Response evidence */}
            {incident.response_evidence && (
              <div className="mt-3 rounded-lg border bg-secondary/30 p-3">
                <p className="mb-2 text-[0.7rem] font-semibold uppercase tracking-wider text-muted-foreground">
                  Response Evidence
                </p>
                <TwoColGrid>
                  <Field
                    label="Dominant CAN ID"
                    value={incident.response_evidence.dominant_can_id ?? "—"}
                    mono
                  />
                  <Field
                    label="Dominant Share"
                    value={
                      incident.response_evidence.dominant_can_id_share_pct != null
                        ? `${incident.response_evidence.dominant_can_id_share_pct.toFixed(2)}%`
                        : "—"
                    }
                    mono
                  />
                </TwoColGrid>
                {(incident.response_evidence.unexpected_can_ids ?? []).length > 0 && (
                  <div className="mt-2">
                    <p className="mb-1 text-[0.7rem] text-muted-foreground">Unexpected CAN IDs:</p>
                    <div className="flex flex-wrap gap-1">
                      {incident.response_evidence.unexpected_can_ids.map((id) => (
                        <span
                          key={id}
                          className="rounded border bg-secondary px-1.5 py-0.5 font-mono text-xs"
                        >
                          {id}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}
          </ReportSection>

          {/* Section 4 — Model evidence */}
          <ReportSection title="Model Evidence" icon={<Info className="size-4" />}>
            <TwoColGrid>
              <Field
                label="Peak Anomaly Score"
                value={peakScore != null ? peakScore.toFixed(6) : "—"}
                mono
              />
              <Field
                label="Avg Anomaly Score"
                value={avgScore != null ? avgScore.toFixed(6) : "—"}
                mono
              />
              <Field label="Detection Algorithm" value="Isolation Forest (Scikit-learn)" />
              <Field label="Classification Method" value="Multi-dimensional Feature Divergence" />
            </TwoColGrid>

            {/* Detection reasons */}
            {(incident.reasons ?? []).length > 0 && (
              <div className="mt-3">
                <p className="mb-2 text-[0.7rem] font-semibold uppercase tracking-wider text-muted-foreground">
                  Detection Reasons
                </p>
                <ul className="space-y-1.5">
                  {(incident.reasons ?? []).map((r, i) => (
                    <li
                      key={`${r.code}-${i}`}
                      className="rounded border border-border/60 bg-secondary/30 px-3 py-2 text-xs"
                    >
                      <span className="font-semibold font-mono text-foreground">{r.code}</span>
                      <span className="mx-2 text-muted-foreground">·</span>
                      <span className="text-muted-foreground">{r.message}</span>
                    </li>
                  ))}
                </ul>
              </div>
            )}

            {/* Evidence summary */}
            {incident.summary && (
              <p className="mt-3 rounded border bg-secondary/30 px-3 py-2 text-xs text-muted-foreground">
                {incident.summary}
              </p>
            )}
          </ReportSection>

          {/* Section 5 — Response & process */}
          <ReportSection title="Automated Response" icon={<ShieldCheck className="size-4" />}>
            <TwoColGrid>
              <Field label="Response State" value={incident.response_state ?? "—"} mono />
              <Field
                label="Attack Process PID"
                value={pid != null ? String(pid) : "—"}
                mono
              />
              <Field
                label="Process Return Code"
                value={returnCode != null ? String(returnCode) : "—"}
                mono
                className={
                  returnCode === 0
                    ? "text-emerald-500"
                    : returnCode != null
                      ? "text-destructive"
                      : ""
                }
              />
              <Field
                label="Termination Reason"
                value={terminationReason != null ? String(terminationReason) : "—"}
                mono
              />
            </TwoColGrid>

            {/* Termination result */}
            {returnCode != null && (
              <div
                className={cn(
                  "mt-3 flex items-center gap-2 rounded-lg border px-3 py-2 text-xs",
                  terminationSuccess
                    ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-500"
                    : "border-destructive/30 bg-destructive/10 text-destructive"
                )}
              >
                {terminationSuccess ? (
                  <CheckCircle2 className="size-4 shrink-0" />
                ) : (
                  <XCircle className="size-4 shrink-0" />
                )}
                <span className="font-semibold">
                  {terminationSuccess
                    ? "Attack process confirmed exited cleanly (return code 0)."
                    : `Attack process exited with error code ${returnCode}. Termination may be incomplete.`}
                </span>
              </div>
            )}

            {/* Recovery verification */}
            {recoveryVerification && (
              <div className="mt-3 rounded-lg border bg-secondary/30 p-3">
                <p className="mb-2 text-[0.7rem] font-semibold uppercase tracking-wider text-muted-foreground">
                  Recovery Verification
                </p>
                <div
                  className={cn(
                    "flex items-center gap-2 text-xs",
                    recoveryVerified ? "text-emerald-500" : "text-amber-500"
                  )}
                >
                  {recoveryVerified ? (
                    <CheckCircle2 className="size-4" />
                  ) : (
                    <AlertCircle className="size-4" />
                  )}
                  <span className="font-semibold">
                    {recoveryVerified
                      ? "Recovery verified — normal traffic baseline restored."
                      : "Recovery verification pending or incomplete."}
                  </span>
                </div>
              </div>
            )}
          </ReportSection>

          {/* Section 6 — Raw window features (collapsible on screen, visible in print) */}
          {(incident.windows ?? []).length > 0 && (
            <ReportSection title="Anomalous Window Feature Vectors" icon={<FileText className="size-4" />}>
              <button
                type="button"
                className="flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground print:hidden"
                onClick={() => setShowRawWindows((v) => !v)}
              >
                {showRawWindows ? <ChevronUp className="size-3" /> : <ChevronDown className="size-3" />}
                {showRawWindows ? "Hide" : "Show"} window feature vectors ({incident.windows.length} windows)
              </button>
              <div className={cn("mt-2 max-h-60 space-y-2 overflow-y-auto print:max-h-none print:overflow-visible", !showRawWindows && "hidden print:block")}>
                {incident.windows.map((w) => (
                  <div key={w.window_index} className="rounded border bg-secondary/30 px-3 py-2 text-[0.68rem] print:bg-white print:border-gray-300">
                    <div className="mb-1 flex items-center justify-between">
                      <span className="font-mono font-semibold">Window #{w.window_index}</span>
                      <span
                        className={cn(
                          "rounded px-1.5 py-0.5 text-[0.65rem] font-semibold",
                          w.prediction === "ANOMALY"
                            ? "bg-destructive/15 text-destructive print:text-red-700"
                            : "bg-emerald-500/15 text-emerald-500"
                        )}
                      >
                        {w.prediction}
                      </span>
                    </div>
                    <div className="text-muted-foreground">
                      Anomaly Score: <span className="font-mono font-semibold">{w.anomaly_score.toFixed(6)}</span>
                      {" · "}
                      Start UTC: <span className="font-mono">{fmtTs(w.window_start_utc)}</span>
                      {" · "}
                      Frames: <span className="font-mono">{w.features.total_frames}</span>
                      {" · "}
                      Dominant ID: <span className="font-mono">{incident.response_evidence?.dominant_can_id ?? "—"}</span>
                    </div>
                  </div>
                ))}
              </div>
            </ReportSection>
          )}

          {/* Legal / classification notice */}
          <p className="text-[0.68rem] text-muted-foreground">
            All timestamps are UTC. Response latency values are measured from actual backend event
            records. Frame attribution for ID 0x100 is ESTIMATED because normal and Mode 1 attack
            traffic share the same arbitration ID. Mitigation success is confirmed only when the
            attack process returns code 0.
          </p>
        </div>

        {/* ── Footer actions ── */}
        <div className="flex flex-col gap-2 border-t pt-4 print:hidden sm:flex-row sm:justify-between">
          <Button variant="outline" onClick={onClose} size="sm">
            Close Report
          </Button>
          <div className="flex gap-2">
            <Button
              variant="outline"
              size="sm"
              onClick={() => window.print()}
              className="gap-1.5"
            >
              <Printer className="size-4" />
              Print / Save as PDF
            </Button>
            <Button
              variant="default"
              size="sm"
              onClick={() => exportIncidentCsv(incident)}
              className="gap-1.5"
            >
              <Download className="size-4" />
              Export CSV
            </Button>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}

// ─── Sub-components ──────────────────────────────────────────────────────────

function ReportSection({
  title,
  icon,
  children,
}: {
  title: string;
  icon?: React.ReactNode;
  children: React.ReactNode;
}) {
  return (
    <section className="rounded-lg border border-border/60 bg-secondary/20 p-4">
      <h3 className="mb-3 flex items-center gap-2 text-xs font-bold uppercase tracking-widest text-muted-foreground">
        {icon}
        {title}
      </h3>
      {children}
    </section>
  );
}

function TwoColGrid({
  children,
  className,
}: {
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <dl className={cn("grid grid-cols-1 gap-x-4 gap-y-2 sm:grid-cols-2", className)}>
      {children}
    </dl>
  );
}

function Field({
  label,
  value,
  mono,
  className,
}: {
  label: string;
  value: string;
  mono?: boolean;
  className?: string;
}) {
  return (
    <div>
      <dt className="text-[0.65rem] uppercase tracking-wider text-muted-foreground">{label}</dt>
      <dd className={cn("text-xs font-medium text-foreground", mono && "font-mono", className)}>
        {value || "—"}
      </dd>
    </div>
  );
}

