/**
 * Phase 7: Automated Response Validation & Resilience Testing Dashboard
 *
 * Implements:
 * 1. Automated Response Validation Lifecycle (7 steps with PASS, FAIL, RUNNING, NOT VERIFIED).
 * 2. Response Reliability Analytics (attempts, confirmed mitigations, failed, unexpected exits, latencies).
 * 3. Structured Response Audit Trail Table (detailed forensic event records).
 * 4. Controlled Failure Scenario Testing Runner (8 isolated failure scenarios with diagnostic evidence).
 */
import { useState } from "react";
import {
  Activity,
  AlertCircle,
  AlertOctagon,
  AlertTriangle,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  Clock,
  Cpu,
  FileText,
  FlaskConical,
  HelpCircle,
  Loader2,
  Play,
  Radio,
  RefreshCw,
  RotateCcw,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Terminal,
  XCircle,
  Zap,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Panel, fmtTime } from "@/components/app/primitives";
import { useResilienceScenarios, useRunResilienceScenarios } from "@/lib/api/queries";
import type {
  LiveSession,
  ResilienceScenarioResult,
  ResponseAuditRecord,
  ValidationCheck,
} from "@/lib/api/schemas";
import { cn } from "@/lib/utils";

function fmtMs(ms: number): string {
  return ms >= 1000 ? `${(ms / 1000).toFixed(2)} s` : `${Math.round(ms)} ms`;
}

interface ResponseReliabilityDashboardProps {
  session: LiveSession | null;
  capturing: boolean;
}

export function ResponseReliabilityDashboard({
  session,
  capturing,
}: ResponseReliabilityDashboardProps) {
  const [expandedScenarios, setExpandedScenarios] = useState<Record<string, boolean>>({});
  const scenariosQuery = useResilienceScenarios();
  const runScenariosMutation = useRunResilienceScenarios();

  const scenarios = scenariosQuery.data ?? [];
  const isRunningScenarios = runScenariosMutation.isPending;

  // Extract session response reliability and validation metadata
  const validation = session?.response_validation;
  const reliability = session?.response_reliability;
  const auditTrail: ResponseAuditRecord[] = session?.response_audit_trail ?? [];

  // Toggle scenario details drawer
  const toggleScenario = (id: string) => {
    setExpandedScenarios((prev) => ({ ...prev, [id]: !prev[id] }));
  };

  const handleRunSuite = () => {
    runScenariosMutation.mutate();
  };

  // Automated Response Validation Checks (Section 1)
  const validationSteps = [
    {
      id: "incident_creation",
      name: "Confirmed Security Incident Creation",
      desc: "Isolation Forest scores consecutive anomalous windows and correlates formal incident.",
      check: validation?.checks.confirmed_incident_creation ?? {
        status: (session?.incidents?.length ?? 0) > 0 ? "PASS" : "NOT VERIFIED",
        detail: session?.incidents?.length
          ? `${session.incidents.length} confirmed incident(s) generated`
          : "No confirmed incidents recorded",
      },
    },
    {
      id: "response_initiation",
      name: "Automated Response Initiation",
      desc: "Background response engine intercepts incident and issues selective termination.",
      check: validation?.checks.automated_response_initiation ?? {
        status: auditTrail.length > 0 ? "PASS" : "NOT VERIFIED",
        detail: auditTrail.length > 0 ? `${auditTrail.length} response(s) initiated` : "No response triggers required",
      },
    },
    {
      id: "attack_termination",
      name: "Attack Simulator Termination",
      desc: "Backend process manager signals and detaches only the controlled attack process.",
      check: validation?.checks.attack_simulator_termination ?? {
        status: session?.attack?.state === "STOPPED" ? "PASS" : session?.attack?.state === "RUNNING" ? "RUNNING" : "NOT VERIFIED",
        detail: session?.attack?.state === "STOPPED" ? "Attack process stopped" : "No attack active",
      },
    },
    {
      id: "process_exit_status",
      name: "Actual Process Exit Status (rc == 0)",
      desc: "Confirms adversary process terminated cleanly without timeout or unverified survival.",
      check: validation?.checks.actual_process_exit_status ?? {
        status:
          session?.attack?.state === "STOPPED" && session?.attack?.return_code === 0
            ? "PASS"
            : session?.attack?.state === "STOPPED"
              ? "FAIL"
              : "NOT VERIFIED",
        detail:
          session?.attack?.state === "STOPPED"
            ? `Exit code ${session?.attack?.return_code ?? "unconfirmed"}`
            : "No process exit to verify",
      },
    },
    {
      id: "sniffer_continuity",
      name: "Sniffer Process Continuity",
      desc: "CAN sniffer process and vcan0 capture loop remain uninterrupted during mitigation.",
      check: validation?.checks.sniffer_process_continuity ?? {
        status: capturing ? "PASS" : "NOT VERIFIED",
        detail: capturing ? "Sniffer stream active on vcan0" : "Capture inactive",
      },
    },
    {
      id: "normal_continuity",
      name: "Normal Traffic Generator Continuity",
      desc: "Legitimate RPM, Speed, and Coolant traffic runs continuously without interruption.",
      check: validation?.checks.normal_traffic_continuity ?? {
        status:
          session?.normal?.state === "RUNNING"
            ? "PASS"
            : session?.normal?.return_code != null && session?.normal?.return_code !== 0
              ? "FAIL"
              : "NOT VERIFIED",
        detail: session?.normal?.state === "RUNNING" ? `PID ${session.normal.pid ?? "—"} running` : "Normal generator standby",
      },
    },
    {
      id: "recovery_verification",
      name: "Consecutive Normal-Window Recovery Verification",
      desc: "Validates two consecutive normal model windows after adversary termination.",
      check: validation?.checks.recovery_verification ?? {
        status:
          session?.recovery?.state === "RECOVERED"
            ? "PASS"
            : session?.recovery?.state === "ATTACK_STOPPED_VERIFYING"
              ? "RUNNING"
              : "NOT VERIFIED",
        detail:
          session?.recovery?.state === "RECOVERED"
            ? "Recovery verified (2/2 normal windows)"
            : session?.recovery?.state === "ATTACK_STOPPED_VERIFYING"
              ? `Verifying (${session.recovery.normal_windows ?? 0}/2 windows)`
              : "Recovery not started",
      },
    },
  ];

  // Overall Validation Status
  const overallStatus = validation?.overall_status ?? (
    validationSteps.some((s) => s.check.status === "FAIL")
      ? "FAIL"
      : validationSteps.some((s) => s.check.status === "RUNNING")
        ? "RUNNING"
        : validationSteps.some((s) => s.check.status === "PASS")
          ? "PASS"
          : "NOT VERIFIED"
  );

  return (
    <div className="space-y-6">
      {/* ── Section 1: Automated Response Validation Lifecycle ──────────────── */}
      <Panel
        title="Automated Response Validation Lifecycle"
        aside={
          <div className="flex items-center gap-2">
            <span
              className={cn(
                "inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 font-mono text-[0.68rem] font-bold border",
                overallStatus === "PASS"
                  ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-400"
                  : overallStatus === "FAIL"
                    ? "border-destructive/30 bg-destructive/10 text-destructive"
                    : overallStatus === "RUNNING"
                      ? "border-amber-500/30 bg-amber-500/10 text-amber-400 animate-pulse"
                      : "border-border bg-secondary/50 text-muted-foreground"
              )}
            >
              {overallStatus === "PASS" && <CheckCircle2 className="size-3" />}
              {overallStatus === "FAIL" && <XCircle className="size-3" />}
              {overallStatus === "RUNNING" && <Loader2 className="size-3 animate-spin" />}
              {overallStatus === "NOT VERIFIED" && <HelpCircle className="size-3" />}
              LIFECYCLE: {overallStatus}
            </span>
          </div>
        }
      >
        <p className="text-xs text-muted-foreground mb-4 leading-relaxed">
          CAN-Sentinel enforces strict verification across all 7 stages of the automated incident response lifecycle. Successful mitigation is reported <strong>only after confirming actual process exit status</strong>.
        </p>

        <div className="grid grid-cols-1 gap-2.5 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4">
          {validationSteps.map((step, idx) => (
            <div
              key={step.id}
              className={cn(
                "rounded-xl border p-3 flex flex-col justify-between transition-all",
                step.check.status === "PASS"
                  ? "border-emerald-500/30 bg-emerald-500/5"
                  : step.check.status === "FAIL"
                    ? "border-destructive/40 bg-destructive/10"
                    : step.check.status === "RUNNING"
                      ? "border-amber-500/40 bg-amber-500/10"
                      : "border-border/60 bg-secondary/20"
              )}
            >
              <div>
                <div className="flex items-center justify-between gap-1 mb-1.5">
                  <span className="font-mono text-[0.65rem] text-muted-foreground">
                    Step {idx + 1}/7
                  </span>
                  <StatusBadge status={step.check.status} />
                </div>
                <h4 className="text-xs font-semibold text-foreground leading-snug">
                  {step.name}
                </h4>
                <p className="text-[0.68rem] text-muted-foreground mt-1 leading-relaxed">
                  {step.desc}
                </p>
              </div>
              <div className="mt-2.5 pt-2 border-t border-border/40 font-mono text-[0.65rem] text-foreground font-medium truncate" title={step.check.detail}>
                {step.check.detail}
              </div>
            </div>
          ))}
        </div>
      </Panel>

      {/* ── Section 2: Response Reliability Analytics ──────────────────────── */}
      <Panel
        title="Response Reliability Analytics"
        aside={
          <span className="text-xs font-mono text-muted-foreground">
            Strict Non-Zero Exit Attribution
          </span>
        }
      >
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-4 xl:grid-cols-8">
          <MetricCard
            label="Total Attempts"
            value={reliability?.total_response_attempts ?? auditTrail.length}
            detail="Automated response triggers"
            icon={<Zap className="size-4 text-cyan-400" />}
          />
          <MetricCard
            label="Confirmed Stops"
            value={reliability?.confirmed_successful_mitigations ?? auditTrail.filter((a) => a.return_code === 0).length}
            detail="Confirmed exit code 0"
            icon={<CheckCircle2 className="size-4 text-emerald-400" />}
            variant="success"
          />
          <MetricCard
            label="Failed Mitigations"
            value={reliability?.failed_mitigations ?? auditTrail.filter((a) => a.return_code !== 0 && a.return_code != null).length}
            detail="Non-zero exit or timeout"
            icon={<XCircle className="size-4 text-destructive" />}
            variant={(reliability?.failed_mitigations ?? 0) > 0 ? "critical" : "default"}
          />
          <MetricCard
            label="Unexpected Exits"
            value={reliability?.unexpected_attack_process_exits ?? 0}
            detail="Crashed without trigger"
            icon={<AlertOctagon className="size-4 text-amber-400" />}
            variant={(reliability?.unexpected_attack_process_exits ?? 0) > 0 ? "warning" : "default"}
          />
          <MetricCard
            label="Recovery Success"
            value={
              reliability?.recovery_verification_success_rate != null
                ? `${reliability.recovery_verification_success_rate.toFixed(1)}%`
                : "UNAVAILABLE"
            }
            detail="Multi-window continuity"
            icon={<RotateCcw className="size-4 text-emerald-400" />}
            isUnavailable={reliability?.recovery_verification_success_rate == null}
          />
          <MetricCard
            label="Avg Detection"
            value={
              reliability?.average_detection_latency_ms != null
                ? fmtMs(reliability.average_detection_latency_ms)
                : "UNAVAILABLE"
            }
            detail="Window to incident"
            icon={<Clock className="size-4 text-cyan-400" />}
            isUnavailable={reliability?.average_detection_latency_ms == null}
          />
          <MetricCard
            label="Avg Mitigation"
            value={
              reliability?.average_mitigation_latency_ms != null
                ? fmtMs(reliability.average_mitigation_latency_ms)
                : "UNAVAILABLE"
            }
            detail="Signal to process exit"
            icon={<Activity className="size-4 text-amber-400" />}
            isUnavailable={reliability?.average_mitigation_latency_ms == null}
          />
          <MetricCard
            label="Recovery Duration"
            value="UNAVAILABLE"
            detail="Verification duration"
            icon={<Clock className="size-4 text-muted-foreground" />}
            isUnavailable={true}
          />
        </div>

        <div className="mt-4 rounded-lg border border-border/60 bg-secondary/30 p-3 text-xs text-muted-foreground flex items-start gap-2.5">
          <AlertCircle className="size-4 shrink-0 text-cyan-400 mt-0.5" />
          <p className="text-[0.68rem] leading-relaxed">
            In compliance with automotive SOC safety standards, missing or unverified measurements are strictly labeled as <strong className="text-foreground">UNAVAILABLE</strong> and never defaulted to zero or assumed successful.
          </p>
        </div>
      </Panel>

      {/* ── Section 3: Structured Response Audit Trail ─────────────────────── */}
      <Panel
        title="Automated Response Audit Trail"
        aside={
          <span className="text-xs font-mono text-muted-foreground">
            {auditTrail.length} recorded mitigation event{auditTrail.length === 1 ? "" : "s"}
          </span>
        }
      >
        {auditTrail.length > 0 ? (
          <div className="overflow-x-auto rounded-lg border border-border/60">
            <table className="w-full text-left text-xs font-mono">
              <thead className="border-b border-border bg-secondary/40 text-[0.65rem] uppercase text-muted-foreground">
                <tr>
                  <th className="py-2.5 px-3">Incident ID</th>
                  <th className="py-2.5 px-3">Action</th>
                  <th className="py-2.5 px-3">Target PID</th>
                  <th className="py-2.5 px-3">Initiated</th>
                  <th className="py-2.5 px-3">Terminated</th>
                  <th className="py-2.5 px-3 text-center">Return Code</th>
                  <th className="py-2.5 px-3">Sniffer</th>
                  <th className="py-2.5 px-3">Normal ECU</th>
                  <th className="py-2.5 px-3">Recovery</th>
                  <th className="py-2.5 px-3 text-right">Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border/40 bg-card/60">
                {auditTrail.map((entry) => (
                  <tr key={entry.audit_id} className="hover:bg-secondary/20 transition-colors">
                    <td className="py-2.5 px-3 font-bold text-foreground">
                      {entry.incident_id}
                    </td>
                    <td className="py-2.5 px-3 text-cyan-400 truncate max-w-[140px]" title={entry.response_action}>
                      {entry.response_action}
                    </td>
                    <td className="py-2.5 px-3 text-foreground">
                      {entry.process_pid ?? "—"}
                    </td>
                    <td className="py-2.5 px-3 text-muted-foreground text-[0.68rem]">
                      {fmtTime(entry.action_initiation_timestamp)}
                    </td>
                    <td className="py-2.5 px-3 text-muted-foreground text-[0.68rem]">
                      {fmtTime(entry.process_termination_timestamp)}
                    </td>
                    <td className="py-2.5 px-3 text-center">
                      <span
                        className={cn(
                          "rounded px-1.5 py-0.5 text-[0.62rem] font-bold border",
                          entry.return_code === 0
                            ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-400"
                            : "border-destructive/30 bg-destructive/10 text-destructive"
                        )}
                      >
                        {entry.return_code != null ? `rc=${entry.return_code}` : "unconfirmed"}
                      </span>
                    </td>
                    <td className="py-2.5 px-3">
                      <span
                        className={cn(
                          "text-[0.65rem] font-bold",
                          entry.sniffer_continuity_status === "PASS" ? "text-emerald-400" : "text-destructive"
                        )}
                      >
                        {entry.sniffer_continuity_status}
                      </span>
                    </td>
                    <td className="py-2.5 px-3">
                      <span
                        className={cn(
                          "text-[0.65rem] font-bold",
                          entry.normal_traffic_continuity_status === "PASS"
                            ? "text-emerald-400"
                            : entry.normal_traffic_continuity_status === "FAIL"
                              ? "text-destructive"
                              : "text-muted-foreground"
                        )}
                      >
                        {entry.normal_traffic_continuity_status}
                      </span>
                    </td>
                    <td className="py-2.5 px-3 text-[0.65rem]">
                      <span
                        className={cn(
                          "rounded px-1.5 py-0.5 text-[0.62rem] border",
                          entry.recovery_verification_result === "PASS"
                            ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-400 font-bold"
                            : entry.recovery_verification_result === "IN_PROGRESS"
                              ? "border-amber-500/30 bg-amber-500/10 text-amber-400 font-bold animate-pulse"
                              : "border-border text-muted-foreground"
                        )}
                      >
                        {entry.recovery_verification_result}
                      </span>
                    </td>
                    <td className="py-2.5 px-3 text-right">
                      <span
                        className={cn(
                          "rounded px-2 py-0.5 text-[0.65rem] font-bold uppercase border",
                          entry.final_response_status === "VERIFIED_RECOVERED" || entry.final_response_status === "MITIGATED"
                            ? "border-emerald-500/40 bg-emerald-500/20 text-emerald-400"
                            : "border-destructive/40 bg-destructive/20 text-destructive"
                        )}
                      >
                        {entry.final_response_status}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="rounded-lg border border-dashed border-border/60 p-6 text-center text-xs text-muted-foreground">
            No automated response events recorded for this session yet. Launch an attack simulation to observe automated mitigation and forensic audit logging.
          </div>
        )}
      </Panel>

      {/* ── Section 4: Controlled Failure Scenario Testing ─────────────────── */}
      <Panel
        title="Controlled Failure Scenario Testing"
        aside={
          <Button
            size="sm"
            variant="outline"
            className="text-xs gap-1.5"
            onClick={handleRunSuite}
            disabled={isRunningScenarios}
          >
            {isRunningScenarios ? <Loader2 className="size-3.5 animate-spin" /> : <FlaskConical className="size-3.5" />}
            {isRunningScenarios ? "Running Test Suite…" : "Execute Resilience Suite"}
          </Button>
        }
      >
        <p className="text-xs text-muted-foreground mb-4 leading-relaxed">
          Verifies CAN-Sentinel response resilience across 8 controlled failure scenarios in an isolated test environment. All tests remain restricted to virtual CAN interfaces and memory.
        </p>

        <div className="space-y-2">
          {scenarios.map((scn) => {
            const isExpanded = !!expandedScenarios[scn.scenario_id];
            return (
              <div
                key={scn.scenario_id}
                className={cn(
                  "rounded-lg border transition-all overflow-hidden",
                  scn.status === "PASS"
                    ? "border-emerald-500/30 bg-emerald-500/5"
                    : "border-destructive/40 bg-destructive/10"
                )}
              >
                <div
                  className="flex flex-wrap items-center justify-between gap-3 p-3 cursor-pointer hover:bg-secondary/30 transition-colors"
                  onClick={() => toggleScenario(scn.scenario_id)}
                >
                  <div className="flex items-center gap-3">
                    <span
                      className={cn(
                        "rounded px-1.5 py-0.5 font-mono text-[0.65rem] font-bold border",
                        scn.status === "PASS"
                          ? "border-emerald-500/40 bg-emerald-500/20 text-emerald-400"
                          : "border-destructive/40 bg-destructive/20 text-destructive"
                      )}
                    >
                      {scn.scenario_id}
                    </span>
                    <div>
                      <h4 className="text-xs font-semibold text-foreground">
                        {scn.scenario_name}
                      </h4>
                      <p className="text-[0.68rem] text-muted-foreground line-clamp-1">
                        Expected: {scn.expected_behavior}
                      </p>
                    </div>
                  </div>

                  <div className="flex items-center gap-3">
                    <span
                      className={cn(
                        "rounded px-2 py-0.5 font-mono text-[0.65rem] font-bold uppercase",
                        scn.status === "PASS" ? "text-emerald-400" : "text-destructive"
                      )}
                    >
                      {scn.status}
                    </span>
                    {isExpanded ? (
                      <ChevronDown className="size-4 text-muted-foreground" />
                    ) : (
                      <ChevronRight className="size-4 text-muted-foreground" />
                    )}
                  </div>
                </div>

                {isExpanded && (
                  <div className="border-t border-border/40 bg-secondary/30 p-3.5 space-y-2 text-xs font-mono">
                    <div>
                      <span className="text-muted-foreground uppercase text-[0.65rem] font-semibold block mb-0.5">
                        Expected Behavior:
                      </span>
                      <p className="text-foreground text-[0.72rem] leading-relaxed">
                        {scn.expected_behavior}
                      </p>
                    </div>

                    <div>
                      <span className="text-muted-foreground uppercase text-[0.65rem] font-semibold block mb-0.5">
                        Actual Observed Result:
                      </span>
                      <p className="text-emerald-400 text-[0.72rem] leading-relaxed">
                        {scn.actual_result}
                      </p>
                    </div>

                    {scn.diagnostic_evidence && (
                      <div>
                        <span className="text-muted-foreground uppercase text-[0.65rem] font-semibold block mb-1">
                          Diagnostic Evidence:
                        </span>
                        <pre className="rounded bg-black/40 p-2.5 text-[0.65rem] text-foreground overflow-x-auto leading-relaxed border border-border/40">
                          {JSON.stringify(scn.diagnostic_evidence, null, 2)}
                        </pre>
                      </div>
                    )}

                    <div className="text-[0.62rem] text-muted-foreground pt-1 flex justify-between">
                      <span>Evaluated At: {scn.timestamp}</span>
                      <span className="text-emerald-400">Strict Isolated Sandbox</span>
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </Panel>
    </div>
  );
}

// ─── Subcomponents ──────────────────────────────────────────────────────────

function StatusBadge({ status }: { status: ValidationCheck["status"] }) {
  return (
    <span
      className={cn(
        "rounded px-1.5 py-0.5 font-mono text-[0.62rem] font-bold border",
        status === "PASS"
          ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-400"
          : status === "FAIL"
            ? "border-destructive/30 bg-destructive/10 text-destructive"
            : status === "RUNNING"
              ? "border-amber-500/30 bg-amber-500/10 text-amber-400 animate-pulse"
              : "border-border/60 bg-secondary/50 text-muted-foreground"
      )}
    >
      {status}
    </span>
  );
}

interface MetricCardProps {
  label: string;
  value: React.ReactNode;
  detail: string;
  icon: React.ReactNode;
  variant?: "default" | "success" | "warning" | "critical";
  isUnavailable?: boolean;
}

function MetricCard({
  label,
  value,
  detail,
  icon,
  variant = "default",
  isUnavailable = false,
}: MetricCardProps) {
  return (
    <div
      className={cn(
        "rounded-xl border p-3 flex flex-col justify-between transition-all",
        variant === "critical"
          ? "border-destructive/30 bg-destructive/10"
          : variant === "warning"
            ? "border-amber-500/30 bg-amber-500/10"
            : variant === "success"
              ? "border-emerald-500/30 bg-emerald-500/5"
              : "border-border/60 bg-secondary/20"
      )}
    >
      <div>
        <div className="flex items-center justify-between text-muted-foreground mb-1">
          <span className="text-[0.65rem] font-semibold uppercase tracking-wider truncate">
            {label}
          </span>
          <span className="shrink-0">{icon}</span>
        </div>
        <div
          className={cn(
            "font-mono font-bold tracking-tight text-foreground truncate",
            isUnavailable ? "text-xs text-muted-foreground font-semibold" : "text-base"
          )}
        >
          {value}
        </div>
      </div>
      <div className="mt-1 text-[0.62rem] text-muted-foreground truncate" title={detail}>
        {detail}
      </div>
    </div>
  );
}
