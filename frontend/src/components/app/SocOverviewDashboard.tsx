/**
 * Phase 6: SOC Overview Dashboard
 *
 * Executive real-time summary cards providing security analysts an immediate
 * overview of CAN bus security posture:
 * - Total confirmed incidents
 * - Active attacks
 * - Attack attempts stopped
 * - Successful mitigations (confirmed process terminations only)
 * - Normal traffic status
 * - Current monitoring status
 * - Current recovery status
 *
 * All values derive strictly from actual backend session and attack history data.
 */
import {
  Activity,
  AlertOctagon,
  AlertTriangle,
  CheckCircle2,
  Clock,
  Radio,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Zap,
} from "lucide-react";
import type { LiveSession, SystemStatus } from "@/lib/api/schemas";
import { cn } from "@/lib/utils";

interface SocOverviewDashboardProps {
  session: LiveSession | null;
  status: SystemStatus | undefined;
  totalHistoricalIncidents?: number;
}

export function SocOverviewDashboard({
  session,
  status,
  totalHistoricalIncidents = 0,
}: SocOverviewDashboardProps) {
  const capturing = session?.state === "capturing";
  const incidents = session?.incidents ?? [];
  const confirmedIncidentsCount = incidents.length;
  const totalAllIncidents = Math.max(confirmedIncidentsCount, totalHistoricalIncidents);

  // Attack status
  const attackState = session?.attack?.state ?? "NOT_STARTED";
  const isAttackActive = attackState === "RUNNING";
  const activeAttackMode = session?.attack?.mode;

  // Attack history metrics (Phase 4 & 5 persistent records)
  const attackHistory = session?.attack_history ?? [];
  const stoppedAttempts = attackHistory.filter((a) => a.state === "STOPPED").length;
  const effectiveStopped =
    stoppedAttempts > 0 ? stoppedAttempts : attackState === "STOPPED" ? 1 : 0;

  // Mitigation success: only confirmed exit code 0
  const successfulMitigations = attackHistory.filter(
    (a) => a.state === "STOPPED" && a.return_code === 0,
  ).length;
  const effectiveMitigations =
    successfulMitigations > 0
      ? successfulMitigations
      : attackState === "STOPPED" && session?.attack?.return_code === 0
        ? 1
        : 0;

  // Normal traffic status
  const normalState = session?.normal?.state ?? "NOT_STARTED";
  const isNormalRunning = normalState === "RUNNING";
  const normalPid = session?.normal?.pid;

  // Monitoring status
  const monitoringStatus = capturing
    ? "CAPTURING"
    : session?.state
      ? session.state.toUpperCase()
      : "IDLE";

  // Recovery status
  const recoveryState = session?.recovery?.state ?? "NOT_STARTED";
  const normalWindows = session?.recovery?.normal_windows ?? 0;
  const requiredWindows = session?.recovery?.required_normal_windows ?? 2;

  let recoveryDisplay = "NOT_STARTED";
  let recoveryVariant: "default" | "success" | "warning" | "muted" = "muted";

  if (recoveryState === "RECOVERED") {
    recoveryDisplay = "RECOVERED (Nominal)";
    recoveryVariant = "success";
  } else if (recoveryState === "ATTACK_STOPPED_VERIFYING") {
    recoveryDisplay = `VERIFYING (${normalWindows}/${requiredWindows})`;
    recoveryVariant = "warning";
  } else if (capturing && !isAttackActive) {
    recoveryDisplay = "MONITORING (Nominal)";
    recoveryVariant = "default";
  }

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <Shield className="size-4 text-cyan-400" />
          <h2 className="text-xs font-bold uppercase tracking-widest text-muted-foreground">
            SOC Live Operations Overview
          </h2>
        </div>
        <div className="flex items-center gap-2">
          <span
            className={cn(
              "inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 font-mono text-[0.68rem] font-semibold border",
              capturing
                ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-400"
                : "border-border bg-secondary/60 text-muted-foreground",
            )}
          >
            <span
              className={cn(
                "size-1.5 rounded-full",
                capturing ? "bg-emerald-400 animate-pulse" : "bg-muted-foreground",
              )}
            />
            {capturing ? `LIVE CAN · ${session?.interface ?? "vcan0"}` : "MONITORING STANDBY"}
          </span>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 md:grid-cols-4 2xl:grid-cols-7">
        {/* 1. Confirmed Incidents */}
        <SocCard
          label="Confirmed Incidents"
          value={confirmedIncidentsCount}
          detail={
            totalAllIncidents > confirmedIncidentsCount
              ? `${totalAllIncidents} across all runs`
              : "Isolated Forest verified"
          }
          icon={<ShieldAlert className="size-4" />}
          variant={confirmedIncidentsCount > 0 ? "critical" : "default"}
        />

        {/* 2. Active Attacks */}
        <SocCard
          label="Active Attacks"
          value={isAttackActive ? `Mode ${activeAttackMode ?? 1}` : "0 ACTIVE"}
          detail={isAttackActive ? "Adversary process running" : "No active adversaries"}
          icon={<Zap className="size-4" />}
          variant={isAttackActive ? "critical" : "muted"}
          pulsing={isAttackActive}
        />

        {/* 3. Attack Attempts Stopped */}
        <SocCard
          label="Attempts Stopped"
          value={effectiveStopped}
          detail="Automatic terminations"
          icon={<AlertOctagon className="size-4" />}
          variant={effectiveStopped > 0 ? "warning" : "muted"}
        />

        {/* 4. Successful Mitigations */}
        <SocCard
          label="Confirmed Mitigations"
          value={effectiveMitigations}
          detail={
            effectiveStopped > 0
              ? `${effectiveMitigations}/${effectiveStopped} clean exits (rc=0)`
              : "Exit code 0 verified"
          }
          icon={<CheckCircle2 className="size-4" />}
          variant={effectiveMitigations > 0 ? "success" : "muted"}
        />

        {/* 5. Normal Traffic Status */}
        <SocCard
          label="Normal Traffic"
          value={isNormalRunning ? "RUNNING" : normalState}
          detail={isNormalRunning ? `PID ${normalPid ?? "—"} (RPM/Spd/Cool)` : "Generator inactive"}
          icon={<Activity className="size-4" />}
          variant={isNormalRunning ? "success" : "muted"}
        />

        {/* 6. Current Monitoring Status */}
        <SocCard
          label="Monitoring State"
          value={monitoringStatus}
          detail={
            capturing
              ? `${session?.frames_captured?.toLocaleString() ?? 0} frames captured`
              : "Sniffer not running"
          }
          icon={<Radio className="size-4" />}
          variant={capturing ? "info" : "muted"}
        />

        {/* 7. Current Recovery Status */}
        <SocCard
          label="Recovery Status"
          value={recoveryDisplay}
          detail={
            recoveryState === "RECOVERED"
              ? "Baseline continuity confirmed"
              : recoveryState === "ATTACK_STOPPED_VERIFYING"
                ? "Scoring 2 normal windows"
                : "Nominal operational state"
          }
          icon={<ShieldCheck className="size-4" />}
          variant={recoveryVariant}
        />
      </div>
    </div>
  );
}

// ─── Subcomponent: SocCard ───────────────────────────────────────────────────

interface SocCardProps {
  label: string;
  value: React.ReactNode;
  detail: string;
  icon: React.ReactNode;
  variant?: "default" | "success" | "warning" | "critical" | "info" | "muted";
  pulsing?: boolean;
}

const CARD_VARIANTS: Record<string, string> = {
  default: "border-border/60 bg-card text-foreground",
  success: "border-emerald-500/30 bg-emerald-500/5 text-emerald-400",
  warning: "border-amber-500/30 bg-amber-500/5 text-amber-400",
  critical: "border-destructive/30 bg-destructive/10 text-destructive",
  info: "border-cyan-500/30 bg-cyan-500/5 text-cyan-400",
  muted: "border-border/40 bg-secondary/20 text-muted-foreground",
};

function SocCard({
  label,
  value,
  detail,
  icon,
  variant = "default",
  pulsing = false,
}: SocCardProps) {
  return (
    <div
      className={cn(
        "rounded-xl border p-3 flex flex-col justify-between transition-all",
        CARD_VARIANTS[variant],
        pulsing && "animate-pulse",
      )}
    >
      <div className="flex items-center justify-between gap-1 mb-1">
        <span className="text-[0.65rem] font-semibold uppercase tracking-wider text-muted-foreground truncate">
          {label}
        </span>
        <span className="shrink-0 opacity-80">{icon}</span>
      </div>
      <div className="font-mono text-base font-bold tracking-tight text-foreground truncate">
        {value}
      </div>
      <div className="mt-1 text-[0.65rem] text-muted-foreground truncate" title={detail}>
        {detail}
      </div>
    </div>
  );
}
