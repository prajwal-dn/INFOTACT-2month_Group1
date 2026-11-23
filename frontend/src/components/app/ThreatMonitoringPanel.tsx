/**
 * Phase 6: Threat Monitoring Panel
 *
 * Dedicated SOC threat overview providing immediate analyst awareness of:
 * - Current threat classification (heuristic & response classification)
 * - Latest anomaly score vs nominal baseline
 * - Suspicious CAN IDs with forensic tags
 * - Number of anomalous windows and window spans
 * - Latest confirmed incident summary with quick link to investigation report
 *
 * Only displays information supported by actual backend evidence.
 */
import {
  AlertCircle,
  AlertTriangle,
  ChevronRight,
  Clock,
  ExternalLink,
  FileText,
  Radio,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Zap,
} from "lucide-react";

import { Button } from "@/components/ui/button";
import { Panel, fmtTime } from "@/components/app/primitives";
import { getAttackClassification } from "@/components/app/SecurityAlertModal";
import type { InferenceWindow, LiveIncident } from "@/lib/api/schemas";
import { cn } from "@/lib/utils";

interface ThreatMonitoringPanelProps {
  windows: InferenceWindow[];
  incidents: LiveIncident[];
  capturing: boolean;
  onOpenReport?: (incident: LiveIncident) => void;
  onOpenAlertModal?: (incident: LiveIncident) => void;
}

export function ThreatMonitoringPanel({
  windows,
  incidents,
  capturing,
  onOpenReport,
  onOpenAlertModal,
}: ThreatMonitoringPanelProps) {
  const latestWindow = windows.length > 0 ? windows[windows.length - 1] : null;
  const anomalousWindows = windows.filter((w) => w.prediction === "ANOMALY");
  const anomalyCount = anomalousWindows.length;
  const latestIncident = incidents.length > 0 ? incidents[incidents.length - 1] : null;

  // Active threat classification
  let classificationTitle = "Nominal Baseline";
  let classificationThreat = "Traffic Within Specification";
  let classificationDesc = "No anomalous frame cadence or unexpected arbitration IDs detected.";
  let threatSeverity: "NORMAL" | "MEDIUM" | "HIGH" | "REVIEW" = "NORMAL";

  if (latestIncident) {
    const attackInfo = getAttackClassification(latestIncident);
    classificationTitle = attackInfo.category;
    classificationThreat = attackInfo.threatLevel;
    classificationDesc = attackInfo.description;
    threatSeverity = latestIncident.severity;
  } else if (anomalousWindows.length > 0) {
    classificationTitle = "Statistical Traffic Divergence";
    classificationThreat = "Pending Incident Correlation";
    classificationDesc = "Isolation Forest detected anomaly scores exceeding nominal threshold.";
    threatSeverity = "MEDIUM";
  }

  // Latest score and baseline comparison
  const latestScore = latestWindow ? latestWindow.anomaly_score : null;
  const isLatestAnomalous = latestWindow?.prediction === "ANOMALY";

  // Suspicious CAN IDs
  const suspiciousIds: string[] = Array.from(
    new Set([
      ...(latestIncident?.affected_can_ids ?? []),
      ...(latestIncident?.response_evidence?.unexpected_can_ids ?? []),
      ...(latestWindow?.response_evidence?.unexpected_can_ids ?? []),
    ])
  );

  return (
    <Panel
      title="Active Threat Monitoring"
      aside={
        <div className="flex items-center gap-1.5 font-mono text-xs">
          <span
            className={cn(
              "size-2 rounded-full",
              threatSeverity === "HIGH"
                ? "bg-destructive animate-ping"
                : threatSeverity === "MEDIUM"
                  ? "bg-amber-400"
                  : "bg-emerald-400"
            )}
          />
          <span
            className={cn(
              "font-bold uppercase",
              threatSeverity === "HIGH"
                ? "text-destructive"
                : threatSeverity === "MEDIUM"
                  ? "text-amber-400"
                  : "text-emerald-400"
            )}
          >
            {threatSeverity === "NORMAL" ? "SECURE" : `${threatSeverity} THREAT`}
          </span>
        </div>
      }
    >
      <div className="space-y-4">
        {/* Threat Classification Hero Banner */}
        <div
          className={cn(
            "rounded-xl border p-4 transition-all flex flex-col md:flex-row md:items-center justify-between gap-4",
            threatSeverity === "HIGH"
              ? "border-destructive/40 bg-destructive/10"
              : threatSeverity === "MEDIUM"
                ? "border-amber-500/40 bg-amber-500/10"
                : "border-border/60 bg-secondary/30"
          )}
        >
          <div className="flex items-start gap-3.5">
            <div
              className={cn(
                "rounded-lg p-2.5 shrink-0 mt-0.5",
                threatSeverity === "HIGH"
                  ? "bg-destructive/20 text-destructive"
                  : threatSeverity === "MEDIUM"
                    ? "bg-amber-500/20 text-amber-500"
                    : "bg-emerald-500/20 text-emerald-400"
              )}
            >
              {threatSeverity === "HIGH" ? (
                <ShieldAlert className="size-6" />
              ) : threatSeverity === "MEDIUM" ? (
                <AlertTriangle className="size-6" />
              ) : (
                <ShieldCheck className="size-6" />
              )}
            </div>

            <div className="space-y-1">
              <div className="flex flex-wrap items-center gap-2">
                <span className="font-display text-base font-bold text-foreground">
                  {classificationTitle}
                </span>
                <span
                  className={cn(
                    "rounded px-2 py-0.5 font-mono text-[0.68rem] font-bold uppercase border",
                    threatSeverity === "HIGH"
                      ? "border-destructive/40 bg-destructive/20 text-destructive"
                      : threatSeverity === "MEDIUM"
                        ? "border-amber-500/40 bg-amber-500/20 text-amber-400"
                        : "border-emerald-500/40 bg-emerald-500/20 text-emerald-400"
                  )}
                >
                  {classificationThreat}
                </span>
              </div>
              <p className="text-xs text-muted-foreground leading-relaxed max-w-2xl">
                {classificationDesc}
              </p>
            </div>
          </div>

          {latestIncident && (
            <div className="flex shrink-0 flex-wrap gap-2 md:flex-col items-end justify-center">
              {onOpenAlertModal && (
                <Button
                  size="sm"
                  variant="destructive"
                  className="text-xs gap-1.5"
                  onClick={() => onOpenAlertModal(latestIncident)}
                >
                  <ShieldAlert className="size-3.5" />
                  View SOC Alert
                </Button>
              )}
              {onOpenReport && (
                <Button
                  size="sm"
                  variant="outline"
                  className="text-xs gap-1.5"
                  onClick={() => onOpenReport(latestIncident)}
                >
                  <FileText className="size-3.5" />
                  Investigation Report
                </Button>
              )}
            </div>
          )}
        </div>

        {/* Threat Evidence Matrix */}
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4">
          {/* Latest Anomaly Score */}
          <div className="rounded-lg border border-border/60 bg-secondary/30 p-3 space-y-1">
            <div className="flex items-center justify-between text-muted-foreground">
              <span className="text-[0.68rem] font-semibold uppercase tracking-wider">Latest Score</span>
              <Radio className="size-3.5 text-cyan-400" />
            </div>
            <div className="flex items-baseline gap-2">
              <span
                className={cn(
                  "font-mono text-xl font-bold",
                  isLatestAnomalous ? "text-destructive" : "text-emerald-400"
                )}
              >
                {latestScore != null ? latestScore.toFixed(4) : "—"}
              </span>
              <span className="text-[0.68rem] text-muted-foreground font-mono">
                {isLatestAnomalous ? "(ANOMALY)" : "(NORMAL)"}
              </span>
            </div>
            <div className="text-[0.65rem] text-muted-foreground">
              Threshold: ~0.75 Contamination: 0.05
            </div>
          </div>

          {/* Suspicious CAN IDs */}
          <div className="rounded-lg border border-border/60 bg-secondary/30 p-3 space-y-1">
            <div className="flex items-center justify-between text-muted-foreground">
              <span className="text-[0.68rem] font-semibold uppercase tracking-wider">Suspicious CAN IDs</span>
              <Zap className="size-3.5 text-amber-400" />
            </div>
            <div className="flex flex-wrap gap-1 min-h-[1.75rem] items-center">
              {suspiciousIds.length > 0 ? (
                suspiciousIds.map((id) => (
                  <span
                    key={id}
                    className="rounded border border-destructive/40 bg-destructive/10 px-1.5 py-0.5 font-mono text-xs font-semibold text-destructive"
                  >
                    {id}
                  </span>
                ))
              ) : (
                <span className="font-mono text-xs text-muted-foreground">None identified</span>
              )}
            </div>
            <div className="text-[0.65rem] text-muted-foreground">
              {suspiciousIds.length > 0 ? `${suspiciousIds.length} IDs under observation` : "Matrix nominal"}
            </div>
          </div>

          {/* Anomalous Windows */}
          <div className="rounded-lg border border-border/60 bg-secondary/30 p-3 space-y-1">
            <div className="flex items-center justify-between text-muted-foreground">
              <span className="text-[0.68rem] font-semibold uppercase tracking-wider">Anomalous Windows</span>
              <AlertCircle className="size-3.5 text-destructive" />
            </div>
            <div className="flex items-baseline gap-2">
              <span
                className={cn(
                  "font-mono text-xl font-bold",
                  anomalyCount > 0 ? "text-destructive" : "text-foreground"
                )}
              >
                {anomalyCount}
              </span>
              <span className="text-[0.68rem] text-muted-foreground font-mono">
                / {windows.length} scored
              </span>
            </div>
            <div className="text-[0.65rem] text-muted-foreground">
              {anomalyCount > 0
                ? `${((anomalyCount / Math.max(1, windows.length)) * 100).toFixed(1)}% anomaly rate`
                : "No anomalous windows"}
            </div>
          </div>

          {/* Latest Confirmed Incident */}
          <div className="rounded-lg border border-border/60 bg-secondary/30 p-3 space-y-1">
            <div className="flex items-center justify-between text-muted-foreground">
              <span className="text-[0.68rem] font-semibold uppercase tracking-wider">Latest Incident</span>
              <Clock className="size-3.5 text-muted-foreground" />
            </div>
            <div className="font-mono text-base font-bold text-foreground truncate">
              {latestIncident ? latestIncident.incident_id : "None confirmed"}
            </div>
            <div className="text-[0.65rem] text-muted-foreground truncate">
              {latestIncident
                ? `${latestIncident.severity} · ${latestIncident.status}`
                : "Awaiting anomaly cluster"}
            </div>
          </div>
        </div>
      </div>
    </Panel>
  );
}

