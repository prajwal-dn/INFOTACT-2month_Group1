import { useState } from "react";
import {
  AlertCircle,
  AlertTriangle,
  CheckCircle2,
  ChevronDown,
  ChevronUp,
  Clock,
  ExternalLink,
  FileText,
  Loader2,
  Radio,
  ShieldAlert,
  ShieldCheck,
  Zap,
} from "lucide-react";

import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { fmtTime } from "@/components/app/primitives";
import type { LiveIncident, LiveSession } from "@/lib/api/schemas";
import { cn } from "@/lib/utils";

interface SecurityAlertModalProps {
  incident: LiveIncident | null;
  session: LiveSession | null;
  isOpen: boolean;
  onClose: () => void;
  onOpenAnalysis: (analysisId: string) => void;
  onOpenReport?: (incident: LiveIncident) => void;
}

export function getAttackClassification(incident: LiveIncident): {
  category: string;
  threatLevel: string;
  description: string;
} {
  const responseObj = incident.response_result as Record<string, any> | undefined;
  const planClassification = responseObj?.["plan"]?.classification as string | undefined;

  const reasonCodes = (incident.reasons ?? []).map((r) => r.code?.toUpperCase() ?? "");
  const hasFlood = reasonCodes.includes("HIGH_TRAFFIC_VOLUME") || reasonCodes.includes("DOMINANT_CAN_ID");
  const hasUnexpected = reasonCodes.includes("UNEXPECTED_CAN_ID") || reasonCodes.includes("EXTENDED_FRAME_PRESENT");

  if (planClassification === "HIGH_FREQUENCY_FLOOD" || (hasFlood && !hasUnexpected)) {
    return {
      category: "CAN Bus Flooding / Denial-of-Service (DoS)",
      threatLevel: "Severe Bus Contention",
      description:
        "Excessive frame transmission volume overwhelming arbitration priority, violating nominal ECU bus cadence.",
    };
  }

  if (planClassification === "UNEXPECTED_CAN_ID" || (hasUnexpected && !hasFlood)) {
    return {
      category: "Unauthorized CAN ID Injection (Spoofing / Recon)",
      threatLevel: "Out-of-Specification Frames",
      description:
        "Frame transmission using CAN arbitration IDs or extended format not present in the baseline vehicle matrix.",
    };
  }

  if (planClassification === "MIXED_EVIDENCE" || (hasFlood && hasUnexpected)) {
    return {
      category: "Multi-Vector Infiltration (Flood + Rogue ID)",
      threatLevel: "Compound Threat Vector",
      description:
        "Simultaneous high-frequency frame exhaustion combined with unauthorized CAN arbitration IDs.",
    };
  }

  return {
    category: planClassification || "Heuristic CAN Bus Anomaly",
    threatLevel: "Statistical Traffic Deviation",
    description: incident.summary || "Isolation Forest multi-dimensional feature divergence detected on virtual bus.",
  };
}

export function SecurityAlertModal({
  incident,
  session,
  isOpen,
  onClose,
  onOpenAnalysis,
  onOpenReport,
}: SecurityAlertModalProps) {
  const [showRawFeatures, setShowRawFeatures] = useState(false);

  if (!incident) return null;

  const attackInfo = getAttackClassification(incident);
  const severity = incident.severity;

  // Anomaly score calculation
  const scores = (incident.windows ?? []).map((w) => w.anomaly_score);
  const peakAnomalyScore = scores.length > 0 ? Math.max(...scores) : 0.8;
  const avgAnomalyScore = scores.length > 0 ? scores.reduce((a, b) => a + b, 0) / scores.length : 0.8;

  // Response status calculation
  const responseResult = incident.response_result as Record<string, any> | undefined;
  const attackState = session?.attack?.state;
  const recoveryState = session?.recovery?.state;
  const normalWindows = session?.recovery?.normal_windows ?? 0;
  const requiredNormalWindows = session?.recovery?.required_normal_windows ?? 2;

  // Step 1: Detection confirmed (always true since this is a confirmed incident)
  const step1Confirmed = true;

  // Step 2: Response initiated
  const step2Initiated =
    incident.analysis_registered === true ||
    incident.response_state !== "QUEUED" ||
    attackState === "STOPPED" ||
    recoveryState !== "NOT_STARTED";

  // Step 3: Malicious simulator terminated
  const step3Terminated =
    attackState === "STOPPED" ||
    recoveryState === "ATTACK_STOPPED_VERIFYING" ||
    recoveryState === "RECOVERED" ||
    incident.analysis_registered === true;

  // Step 4: Recovery verification pending / active
  const isVerifying = recoveryState === "ATTACK_STOPPED_VERIFYING";
  const step4Pending = isVerifying || recoveryState === "RECOVERED";

  // Step 5: Recovery verified
  const step5Verified =
    recoveryState === "RECOVERED" || responseResult?.["verification"]?.recovery?.verified === true;

  const affectedIds = incident.affected_can_ids ?? [];
  const responseEvidence = incident.response_evidence;
  const dominantId = responseEvidence?.dominant_can_id;
  const dominantShare = responseEvidence?.dominant_can_id_share_pct;
  const unexpectedIds = responseEvidence?.unexpected_can_ids ?? [];

  return (
    <Dialog open={isOpen} onOpenChange={(open) => !open && onClose()}>
      <DialogContent className="max-h-[92vh] max-w-3xl overflow-y-auto border-destructive/50 bg-background/95 p-6 shadow-2xl backdrop-blur-md sm:rounded-xl">
        {/* Header with SOC styling */}
        <DialogHeader className="space-y-2 border-b border-border/60 pb-4 text-left">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div className="flex items-center gap-2">
              <span className="relative flex size-3">
                <span className="absolute inline-flex size-full animate-ping rounded-full bg-destructive opacity-75" />
                <span className="relative inline-flex size-3 rounded-full bg-destructive" />
              </span>
              <span className="font-mono text-xs font-bold uppercase tracking-wider text-destructive">
                SOC Security Alert · Real-Time Incident
              </span>
            </div>

            <div className="flex items-center gap-2">
              <span className="rounded-md border bg-secondary/80 px-2 py-0.5 font-mono text-xs font-semibold text-foreground">
                {incident.incident_id}
              </span>
              <span className="rounded-md border border-border/80 bg-secondary/50 px-2 py-0.5 font-mono text-xs text-muted-foreground">
                Interface: {session?.interface ?? "vcan0"}
              </span>
            </div>
          </div>

          <DialogTitle className="flex items-center gap-2.5 font-display text-xl sm:text-2xl font-bold tracking-tight text-foreground">
            {severity === "HIGH" ? (
              <ShieldAlert className="size-6 shrink-0 text-destructive" />
            ) : severity === "MEDIUM" ? (
              <AlertTriangle className="size-6 shrink-0 text-amber-500" />
            ) : (
              <AlertCircle className="size-6 shrink-0 text-primary" />
            )}
            <span>{attackInfo.category}</span>
          </DialogTitle>

          <DialogDescription className="text-xs sm:text-sm text-muted-foreground">
            {attackInfo.description}
          </DialogDescription>
        </DialogHeader>

        {/* Severity & Threat Classification Bar */}
        <div className="grid grid-cols-2 gap-3 rounded-lg border bg-secondary/30 p-3 sm:grid-cols-4">
          <div>
            <span className="text-[0.7rem] uppercase tracking-wider text-muted-foreground">Severity</span>
            <div className="mt-1">
              <span
                className={cn(
                  "inline-flex items-center gap-1 rounded px-2 py-0.5 text-xs font-bold",
                  severity === "HIGH"
                    ? "border border-destructive/40 bg-destructive/15 text-destructive"
                    : severity === "MEDIUM"
                      ? "border border-amber-500/40 bg-amber-500/15 text-amber-500"
                      : "border border-primary/40 bg-primary/15 text-primary",
                )}
              >
                {severity} SEVERITY
              </span>
            </div>
          </div>

          <div>
            <span className="text-[0.7rem] uppercase tracking-wider text-muted-foreground">Detection Timestamp</span>
            <div className="mt-1 font-mono text-xs font-semibold text-foreground" title={incident.start_time_utc}>
              {fmtTime(incident.start_time_utc)} UTC
            </div>
          </div>

          <div>
            <span className="text-[0.7rem] uppercase tracking-wider text-muted-foreground">Peak Threat Score</span>
            <div className="mt-1 flex items-baseline gap-1.5 font-mono text-xs">
              <span className="font-bold text-destructive">{peakAnomalyScore.toFixed(4)}</span>
              <span className="text-[0.68rem] text-muted-foreground">/ 1.0</span>
            </div>
          </div>

          <div>
            <span className="text-[0.7rem] uppercase tracking-wider text-muted-foreground">Window Scope</span>
            <div className="mt-1 font-mono text-xs font-semibold text-foreground">
              #{incident.start_window} – #{incident.end_window} ({incident.window_count}s)
            </div>
          </div>
        </div>

        {/* Suspicious CAN IDs and Anomaly Evidence */}
        <div className="space-y-3 rounded-lg border border-border/80 bg-card p-4">
          <div className="flex items-center justify-between">
            <h4 className="text-xs font-bold uppercase tracking-wider text-muted-foreground">
              Suspicious CAN Arbitration IDs &amp; Telemetry Evidence
            </h4>
            <span className="font-mono text-xs text-muted-foreground">
              {affectedIds.length} target ID{affectedIds.length === 1 ? "" : "s"}
            </span>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            {affectedIds.length > 0 ? (
              affectedIds.map((id) => (
                <div
                  key={id}
                  className="flex items-center gap-1.5 rounded-md border border-destructive/30 bg-destructive/10 px-2.5 py-1 font-mono text-xs font-bold text-destructive"
                >
                  <Zap className="size-3 text-destructive" />
                  <span>{id}</span>
                  {dominantId === id && dominantShare !== undefined && (
                    <span className="rounded bg-destructive/20 px-1 py-0.2 text-[0.65rem] font-normal text-destructive">
                      {dominantShare.toFixed(1)}% volume
                    </span>
                  )}
                  {unexpectedIds.includes(id) && (
                    <span className="rounded bg-destructive/20 px-1 py-0.2 text-[0.65rem] font-normal text-destructive">
                      out-of-spec
                    </span>
                  )}
                </div>
              ))
            ) : (
              <span className="text-xs text-muted-foreground">No specific ID isolated</span>
            )}

            {unexpectedIds.length > 0 && !affectedIds.some((id) => unexpectedIds.includes(id)) && (
              <div className="text-xs text-destructive">
                Unexpected IDs observed: {unexpectedIds.join(", ")}
              </div>
            )}
          </div>

          {/* Model Evidence Reasons */}
          {incident.reasons && incident.reasons.length > 0 && (
            <div className="mt-2 space-y-1.5 border-t border-border/60 pt-2">
              <span className="text-[0.7rem] font-semibold uppercase tracking-wider text-muted-foreground">
                Model Anomaly Indicators:
              </span>
              <ul className="space-y-1 text-xs">
                {incident.reasons.map((r, i) => (
                  <li key={i} className="flex items-start gap-2">
                    <span className="mt-0.5 rounded bg-secondary px-1.5 py-0.5 font-mono text-[0.68rem] font-semibold text-foreground">
                      {r.code}
                    </span>
                    <span className="text-muted-foreground">{r.message}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>

        {/* Automated Response Status Lifecycle (5 Stages) */}
        <div className="space-y-3 rounded-lg border border-border/80 bg-card p-4">
          <div className="flex items-center justify-between">
            <h4 className="text-xs font-bold uppercase tracking-wider text-muted-foreground">
              Automated Incident Containment &amp; Recovery Lifecycle
            </h4>
            <span className="font-mono text-xs font-semibold text-primary">ISO 11898 SOC Playbook</span>
          </div>

          <div className="space-y-2.5">
            {/* Stage 1: Detection confirmed */}
            <ResponseStep
              number={1}
              title="Detection confirmed"
              status={step1Confirmed ? "complete" : "pending"}
              description={`Isolation Forest model confirmed anomalous pattern across ${incident.window_count} window(s) (Peak score ${peakAnomalyScore.toFixed(4)}).`}
            />

            {/* Stage 2: Response initiated */}
            <ResponseStep
              number={2}
              title="Response initiated"
              status={step2Initiated ? "complete" : "in_progress"}
              description={
                step2Initiated
                  ? `Automated mitigation pipeline dispatched (${incident.response_state ?? "INITIATED"}).`
                  : "Queued for automatic security mitigation execution."
              }
            />

            {/* Stage 3: Malicious simulator terminated */}
            <ResponseStep
              number={3}
              title="Malicious simulator terminated"
              status={
                step3Terminated
                  ? "complete"
                  : attackState === "RUNNING"
                    ? "in_progress"
                    : "pending"
              }
              description={
                step3Terminated
                  ? `Malicious attack simulator terminated on ${session?.interface ?? "vcan0"}${session?.attack?.pid ? ` (PID ${session.attack.pid})` : ""}.`
                  : attackState === "RUNNING"
                    ? "Transmitting termination signal to attack simulator process..."
                    : "No active simulator process flagged."
              }
            />

            {/* Stage 4: Recovery verification pending */}
            <ResponseStep
              number={4}
              title="Recovery verification pending"
              status={
                step5Verified
                  ? "complete"
                  : isVerifying
                    ? "in_progress"
                    : "pending"
              }
              description={
                step5Verified
                  ? "Recovery verification concluded successfully."
                  : isVerifying
                    ? `Telemetry verification active: ${normalWindows} / ${requiredNormalWindows} consecutive normal windows confirmed.`
                    : "Awaiting simulator process cessation to begin recovery telemetry verification."
              }
            />

            {/* Stage 5: Recovery verified */}
            <ResponseStep
              number={5}
              title="Recovery verified"
              status={
                step5Verified
                  ? "complete"
                  : isVerifying
                    ? "pending"
                    : "pending"
              }
              description={
                step5Verified
                  ? `Telemetry verified: Bus traffic returned to nominal baseline with ${requiredNormalWindows} consecutive normal windows.`
                  : `Waiting for ${requiredNormalWindows - normalWindows} more normal window(s) to confirm complete bus recovery.`
              }
            />
          </div>
        </div>

        {/* Expandable Technical Telemetry Section */}
        <div className="rounded-lg border border-border/60 bg-secondary/20 p-3">
          <button
            type="button"
            onClick={() => setShowRawFeatures((prev) => !prev)}
            className="flex w-full items-center justify-between text-xs font-semibold text-muted-foreground hover:text-foreground"
          >
            <span>Telemetry Features &amp; Model Vector</span>
            {showRawFeatures ? <ChevronUp className="size-4" /> : <ChevronDown className="size-4" />}
          </button>

          {showRawFeatures && (
            <div className="mt-3 space-y-3 font-mono text-xs">
              <div className="grid grid-cols-2 gap-2 text-[0.72rem] sm:grid-cols-3">
                <div className="rounded border bg-background/50 p-2">
                  <span className="text-muted-foreground">Total Windows:</span> {incident.windows?.length ?? 0}
                </div>
                <div className="rounded border bg-background/50 p-2">
                  <span className="text-muted-foreground">Avg Score:</span> {avgAnomalyScore.toFixed(4)}
                </div>
                <div className="rounded border bg-background/50 p-2">
                  <span className="text-muted-foreground">Dominant Share:</span> {dominantShare?.toFixed(2) ?? "—"}%
                </div>
              </div>

              {incident.windows && incident.windows.length > 0 && incident.windows[0] && (
                <div className="rounded border bg-background/80 p-2.5">
                  <p className="mb-1 text-[0.7rem] uppercase text-muted-foreground">
                    First Anomalous Window #{incident.windows[0].window_index} Feature Vector:
                  </p>
                  <pre className="max-h-28 overflow-x-auto text-[0.68rem] text-muted-foreground">
                    {JSON.stringify(incident.windows[0].features, null, 2)}
                  </pre>
                </div>
              )}
            </div>
          )}
        </div>

        {/* Modal Footer with Actions */}
        <DialogFooter className="flex flex-col-reverse gap-2 sm:flex-row sm:justify-between sm:space-x-2 pt-2">
          <Button variant="outline" onClick={onClose} className="w-full sm:w-auto">
            Acknowledge &amp; Dismiss Alert
          </Button>

          <div className="flex flex-col sm:flex-row gap-2 w-full sm:w-auto">
            {onOpenReport && (
              <Button
                variant="secondary"
                className="w-full sm:w-auto gap-1.5"
                onClick={() => {
                  onClose();
                  onOpenReport(incident);
                }}
              >
                <FileText className="size-4" />
                View Investigation Report
              </Button>
            )}

            {incident.analysis_id && (
              <Button
                variant="default"
                className="w-full sm:w-auto bg-destructive text-destructive-foreground hover:bg-destructive/90"
                onClick={() => {
                  onClose();
                  onOpenAnalysis(incident.analysis_id!);
                }}
              >
                <ExternalLink className="mr-1.5 size-4" />
                Open Full Incident Dossier ({incident.incident_id})
              </Button>
            )}
          </div>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function ResponseStep({
  number,
  title,
  status,
  description,
}: {
  number: number;
  title: string;
  status: "complete" | "in_progress" | "pending";
  description: string;
}) {
  return (
    <div className="flex items-start gap-3 text-xs">
      <div className="mt-0.5 shrink-0">
        {status === "complete" ? (
          <CheckCircle2 className="size-4 text-emerald-500" />
        ) : status === "in_progress" ? (
          <Loader2 className="size-4 animate-spin text-amber-500" />
        ) : (
          <div className="flex size-4 items-center justify-center rounded-full border border-muted-foreground/40 font-mono text-[0.65rem] text-muted-foreground">
            {number}
          </div>
        )}
      </div>

      <div className="flex-1 space-y-0.5">
        <div className="flex items-center gap-2">
          <span
            className={cn(
              "font-medium",
              status === "complete"
                ? "text-foreground font-semibold"
                : status === "in_progress"
                  ? "text-amber-500 font-semibold"
                  : "text-muted-foreground",
            )}
          >
            {title}
          </span>
          <span
            className={cn(
              "rounded px-1.5 py-0.2 text-[0.65rem] font-semibold uppercase",
              status === "complete"
                ? "bg-emerald-500/15 text-emerald-500"
                : status === "in_progress"
                  ? "bg-amber-500/15 text-amber-500"
                  : "bg-secondary text-muted-foreground",
            )}
          >
            {status === "complete" ? "Confirmed" : status === "in_progress" ? "In Progress" : "Pending"}
          </span>
        </div>
        <p className="text-[0.75rem] text-muted-foreground">{description}</p>
      </div>
    </div>
  );
}

