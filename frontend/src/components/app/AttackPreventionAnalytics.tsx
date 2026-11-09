/**
 * AttackPreventionAnalytics
 *
 * Phase 4: Professional Attack Prevention Analytics Dashboard.
 *
 * All values are derived from actual backend session data via
 * useAttackAnalytics. No values are hardcoded or fabricated.
 *
 * RIGOROUS MEASUREMENT:
 *   - Attack attempts counted from persistent session attack history (supports repeated/mixed attacks).
 *   - Normal traffic interruptions measured strictly by abnormal termination / process crash (manual user stops excluded).
 *   - Millisecond response latency computed from first anomaly window -> process termination.
 *   - Frame attribution during concurrent Mode 1 clearly labeled as ESTIMATED (0x100 shared).
 *   - False positive validation ground truth is explicitly labeled as UNAVAILABLE.
 */
import { useEffect, useRef } from "react";
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
  TrendingDown,
  XCircle,
  Zap,
} from "lucide-react";
import { Panel } from "@/components/app/primitives";
import { cn } from "@/lib/utils";
import type { AttackAnalytics, AttackModeStats, LatencyDataPoint, TrafficDataPoint } from "@/lib/use-attack-analytics";

// ─── Helpers ─────────────────────────────────────────────────────────────────

function fmt(n: number, decimals = 0): string {
  return n.toLocaleString(undefined, {
    minimumFractionDigits: decimals,
    maximumFractionDigits: decimals,
  });
}

function pct(n: number, total: number): string {
  if (total === 0) return "—";
  return `${((n / total) * 100).toFixed(0)}%`;
}

// ─── Metric Card ─────────────────────────────────────────────────────────────

interface MetricCardProps {
  icon: React.ReactNode;
  label: string;
  value: React.ReactNode;
  sub?: string;
  badge?: string;
  variant?: "default" | "success" | "warning" | "critical" | "info" | "muted";
}

const CARD_VARIANTS: Record<string, string> = {
  default:  "border-border/60 bg-card",
  success:  "border-emerald-500/30 bg-emerald-500/5",
  warning:  "border-amber-500/30 bg-amber-500/5",
  critical: "border-destructive/30 bg-destructive/5",
  info:     "border-cyan-500/30 bg-cyan-500/5",
  muted:    "border-border/40 bg-secondary/30",
};

const VALUE_VARIANTS: Record<string, string> = {
  default:  "text-foreground",
  success:  "text-emerald-500",
  warning:  "text-amber-500",
  critical: "text-destructive",
  info:     "text-cyan-400",
  muted:    "text-muted-foreground",
};

function MetricCard({ icon, label, value, sub, badge, variant = "default" }: MetricCardProps) {
  return (
    <div className={cn("rounded-xl border p-4 flex flex-col gap-1.5", CARD_VARIANTS[variant])}>
      <div className="flex items-center justify-between gap-1">
        <div className={cn("flex items-center gap-1.5 text-[0.68rem] font-semibold uppercase tracking-wider", VALUE_VARIANTS[variant])}>
          {icon}
          {label}
        </div>
        {badge && (
          <span className="rounded border border-amber-500/30 bg-amber-500/10 px-1 py-px font-mono text-[0.55rem] font-bold text-amber-400 uppercase">
            {badge}
          </span>
        )}
      </div>
      <div className={cn("font-mono text-2xl font-bold leading-none", VALUE_VARIANTS[variant])}>
        {value}
      </div>
      {sub && (
        <div className="text-[0.68rem] text-muted-foreground leading-snug">{sub}</div>
      )}
    </div>
  );
}

// ─── Traffic Time Series Chart (Canvas) ──────────────────────────────────────

function TrafficChart({ data }: { data: TrafficDataPoint[] }) {
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas || data.length === 0) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    const dpr = window.devicePixelRatio || 1;
    const W = canvas.clientWidth;
    const H = canvas.clientHeight;
    canvas.width = W * dpr;
    canvas.height = H * dpr;
    ctx.scale(dpr, dpr);

    ctx.clearRect(0, 0, W, H);

    const PAD_L = 44;
    const PAD_R = 8;
    const PAD_T = 12;
    const PAD_B = 36;

    const chartW = W - PAD_L - PAD_R;
    const chartH = H - PAD_T - PAD_B;
    const n = data.length;
    const barW = Math.max(2, (chartW / n) - 1);
    const maxFrames = Math.max(...data.map((d) => d.totalFrames), 1);

    // Grid lines
    ctx.strokeStyle = "rgba(255,255,255,0.06)";
    ctx.lineWidth = 1;
    const gridLines = 4;
    for (let i = 0; i <= gridLines; i++) {
      const y = PAD_T + (chartH * i) / gridLines;
      ctx.beginPath();
      ctx.moveTo(PAD_L, y);
      ctx.lineTo(W - PAD_R, y);
      ctx.stroke();

      // Y-axis labels
      const val = Math.round((maxFrames * (gridLines - i)) / gridLines);
      ctx.fillStyle = "rgba(156,163,175,0.7)";
      ctx.font = `${10}px monospace`;
      ctx.textAlign = "right";
      ctx.fillText(String(val), PAD_L - 4, y + 3.5);
    }

    // Bars: stacked normal (green) + malicious (red)
    data.forEach((d, i) => {
      const x = PAD_L + (chartW * i) / n;
      const totalH = (d.totalFrames / maxFrames) * chartH;
      const normalH = (d.normalFrames / maxFrames) * chartH;
      const maliciousH = (d.maliciousFrames / maxFrames) * chartH;

      // Malicious (bottom)
      if (d.maliciousFrames > 0) {
        ctx.fillStyle = d.prediction === "ANOMALY"
          ? "rgba(239,68,68,0.75)"
          : "rgba(239,68,68,0.3)";
        ctx.fillRect(x, PAD_T + chartH - maliciousH, barW, maliciousH);
      }

      // Normal (stacked above malicious)
      if (d.normalFrames > 0) {
        ctx.fillStyle = "rgba(16,185,129,0.70)";
        ctx.fillRect(x, PAD_T + chartH - totalH, barW, normalH);
      }

      // Anomaly score overlay line
      if (d.anomalyScore > 0) {
        const scoreY = PAD_T + chartH * (1 - Math.min(d.anomalyScore, 1));
        ctx.strokeStyle = "rgba(251,191,36,0.6)";
        ctx.lineWidth = 1.5;
        ctx.beginPath();
        ctx.moveTo(x, scoreY);
        ctx.lineTo(x + barW, scoreY);
        ctx.stroke();
      }
    });

    // X-axis labels
    ctx.fillStyle = "rgba(156,163,175,0.7)";
    ctx.font = `${9}px monospace`;
    ctx.textAlign = "center";
    const step = Math.max(1, Math.floor(n / 10));
    data.forEach((d, i) => {
      if (i % step === 0) {
        const x = PAD_L + (chartW * i) / n + barW / 2;
        ctx.fillText(`w${d.windowIndex}`, x, H - PAD_B + 14);
      }
    });

    // Legend
    const legendItems = [
      { color: "rgba(16,185,129,0.8)", label: "Normal (est. 0x100/101/102)" },
      { color: "rgba(239,68,68,0.8)",  label: "Malicious frames" },
      { color: "rgba(251,191,36,0.8)", label: "Anomaly score" },
    ];
    let lx = PAD_L;
    legendItems.forEach(({ color, label }) => {
      ctx.fillStyle = color;
      ctx.fillRect(lx, H - 10, 10, 6);
      ctx.fillStyle = "rgba(156,163,175,0.8)";
      ctx.font = `${9}px monospace`;
      ctx.textAlign = "left";
      ctx.fillText(label, lx + 13, H - 4);
      lx += label.length * 5.2 + 18;
    });
  }, [data]);

  if (data.length === 0) {
    return (
      <div className="flex h-48 items-center justify-center text-sm text-muted-foreground">
        No windows scored yet — start capture and traffic generation
      </div>
    );
  }

  return (
    <canvas
      ref={canvasRef}
      className="w-full"
      style={{ height: 200, display: "block" }}
    />
  );
}

// ─── Termination Comparison Bar ───────────────────────────────────────────────

function TerminationBar({ success, failed }: { success: number; failed: number }) {
  const total = success + failed;
  if (total === 0) {
    return (
      <div className="rounded-lg border border-border/40 bg-secondary/30 p-4 text-center text-sm text-muted-foreground">
        No termination attempts yet — start an attack and wait for automatic response
      </div>
    );
  }

  const successPct = total > 0 ? (success / total) * 100 : 0;

  return (
    <div className="space-y-3">
      <div className="flex gap-3">
        <div className="flex-1 rounded-lg border border-emerald-500/30 bg-emerald-500/8 p-3">
          <div className="flex items-center gap-1.5 text-[0.68rem] font-semibold uppercase tracking-wider text-emerald-500 mb-1">
            <CheckCircle2 className="size-3.5" /> Successful
          </div>
          <div className="font-mono text-2xl font-bold text-emerald-500">{success}</div>
          <div className="text-[0.68rem] text-muted-foreground">
            {pct(success, total)} of confirmed terminations (return_code 0)
          </div>
        </div>
        <div className="flex-1 rounded-lg border border-destructive/30 bg-destructive/8 p-3">
          <div className="flex items-center gap-1.5 text-[0.68rem] font-semibold uppercase tracking-wider text-destructive mb-1">
            <XCircle className="size-3.5" /> Failed
          </div>
          <div className="font-mono text-2xl font-bold text-destructive">{failed}</div>
          <div className="text-[0.68rem] text-muted-foreground">
            {pct(failed, total)} non-zero return code or termination error
          </div>
        </div>
      </div>

      {/* Progress bar */}
      <div className="space-y-1">
        <div className="flex justify-between text-[0.68rem] text-muted-foreground">
          <span>Termination success rate</span>
          <span className="font-mono font-semibold">{successPct.toFixed(0)}%</span>
        </div>
        <div className="h-2 overflow-hidden rounded-full bg-secondary">
          <div
            className="h-full rounded-full bg-emerald-500 transition-all"
            style={{ width: `${successPct}%` }}
          />
        </div>
        <div className="text-[0.65rem] text-muted-foreground">
          Only confirmed after specific process exit verification. In-progress attacks are never counted.
        </div>
      </div>
    </div>
  );
}

// ─── Attack Mode Comparison Table ────────────────────────────────────────────

function ModeComparisonTable({ mode1, mode2 }: { mode1: AttackModeStats; mode2: AttackModeStats }) {
  const rows = [
    { label: "Attempts (Session Total)", m1: mode1.attempts, m2: mode2.attempts },
    { label: "Detected Incidents", m1: mode1.detected, m2: mode2.detected },
    { label: "Terminated (Success, rc=0)", m1: mode1.successfulTerminations, m2: mode2.successfulTerminations },
    { label: "Terminated (Failed, rc≠0)", m1: mode1.failedTerminations, m2: mode2.failedTerminations },
    {
      label: "Avg Response Latency",
      m1: mode1.avgLatencyMs != null ? `${fmt(mode1.avgLatencyMs)} ms` : "—",
      m2: mode2.avgLatencyMs != null ? `${fmt(mode2.avgLatencyMs)} ms` : "—",
    },
    {
      label: "Peak Threat Score",
      m1: mode1.peakAnomalyScore > 0 ? mode1.peakAnomalyScore.toFixed(4) : "—",
      m2: mode2.peakAnomalyScore > 0 ? mode2.peakAnomalyScore.toFixed(4) : "—",
    },
  ];

  return (
    <div className="overflow-x-auto">
      <table className="w-full text-xs">
        <thead>
          <tr className="border-b border-border/60">
            <th className="pb-2 text-left font-semibold text-muted-foreground pr-4">Metric</th>
            <th className="pb-2 text-right font-mono font-semibold text-amber-500 pr-4">
              Mode 1 · Flood (0x100)
            </th>
            <th className="pb-2 text-right font-mono font-semibold text-orange-400">
              Mode 2 · Extended ID (0x999)
            </th>
          </tr>
        </thead>
        <tbody>
          {rows.map(({ label, m1, m2 }) => (
            <tr key={label} className="border-b border-border/30 last:border-0">
              <td className="py-2 text-muted-foreground pr-4">{label}</td>
              <td className="py-2 text-right font-mono font-semibold text-foreground pr-4">
                {m1 === 0 || m1 === "—" ? (
                  <span className="text-muted-foreground/60">{m1 === 0 ? "0" : m1}</span>
                ) : (
                  m1
                )}
              </td>
              <td className="py-2 text-right font-mono font-semibold text-foreground">
                {m2 === 0 || m2 === "—" ? (
                  <span className="text-muted-foreground/60">{m2 === 0 ? "0" : m2}</span>
                ) : (
                  m2
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

// ─── Response Latency Chart (Milliseconds) ────────────────────────────────────

function LatencyChart({ points }: { points: LatencyDataPoint[] }) {
  if (points.length === 0) {
    return (
      <div className="flex h-28 items-center justify-center text-sm text-muted-foreground">
        No incidents detected yet
      </div>
    );
  }

  const validMs = points
    .map((p) => p.detectionToTerminationMs)
    .filter((ms): ms is number => ms != null);
  const maxMs = validMs.length > 0 ? Math.max(...validMs, 100) : 1000;

  return (
    <div className="space-y-3">
      {points.map((p) => {
        const ms = p.detectionToTerminationMs;
        const widthPct = ms != null ? Math.min(100, (ms / maxMs) * 100) : 0;
        const barColor =
          p.severity === "HIGH"
            ? "bg-destructive"
            : p.severity === "MEDIUM"
              ? "bg-amber-500"
              : "bg-primary";

        return (
          <div key={p.incidentId} className="space-y-1">
            <div className="flex items-center justify-between font-mono text-[0.68rem]">
              <span className="text-muted-foreground">{p.incidentId} (Mode {p.attackMode ?? "—"})</span>
              <span className="font-bold text-foreground">
                {ms != null ? `${fmt(ms)} ms` : "Measuring..."}
              </span>
            </div>
            <div className="h-2 overflow-hidden rounded-full bg-secondary">
              <div
                className={cn("h-full rounded-full transition-all", barColor)}
                style={{ width: `${Math.max(4, widthPct)}%` }}
              />
            </div>
            {(p.detectionMs != null || p.mitigationMs != null) && (
              <div className="flex justify-between text-[0.62rem] text-muted-foreground/80 font-mono">
                <span>Detection: {p.detectionMs != null ? `${fmt(p.detectionMs)} ms` : "—"}</span>
                <span>Mitigation: {p.mitigationMs != null ? `${fmt(p.mitigationMs)} ms` : "—"}</span>
              </div>
            )}
          </div>
        );
      })}
      <p className="text-[0.65rem] text-muted-foreground pt-1">
        Latency = actual milliseconds from first anomalous CAN window to attack process termination confirmation.
      </p>
    </div>
  );
}

// ─── Main Component ───────────────────────────────────────────────────────────

interface AttackPreventionAnalyticsProps {
  analytics: AttackAnalytics;
  capturing: boolean;
}

export function AttackPreventionAnalytics({
  analytics,
  capturing,
}: AttackPreventionAnalyticsProps) {
  const {
    totalAttackAttempts,
    totalAttacksDetected,
    successfulTerminations,
    failedTerminations,
    normalTrafficInterruptions,
    avgResponseLatencyMs,
    estimatedNormalFramesDuringAttack,
    estimatedNormalFramesAfterMitigation,
    uncorrelatedAnomalyWindows,
    falsePositiveStatus,
    mode1Stats,
    mode2Stats,
    trafficTimeSeries,
    latencyPoints,
    recoveryVerified,
    verifiedNormalWindows,
    currentAttackMode,
    recoveryState,
  } = analytics;

  const detectionRate =
    totalAttackAttempts > 0
      ? ((totalAttacksDetected / totalAttackAttempts) * 100).toFixed(0)
      : null;

  const aside = (
    <div className="flex items-center gap-2">
      {capturing && (
        <span className="flex items-center gap-1 text-xs text-emerald-500">
          <span className="size-1.5 rounded-full bg-emerald-500 animate-pulse" />
          live
        </span>
      )}
      {currentAttackMode && (
        <span className="rounded border border-amber-500/30 bg-amber-500/10 px-1.5 py-0.5 font-mono text-[0.6rem] font-semibold text-amber-500">
          Mode {currentAttackMode} active
        </span>
      )}
    </div>
  );

  return (
    <Panel title="Attack Prevention Analytics" aside={aside}>
      <div className="space-y-6">

        {/* ── KPI Grid ─────────────────────────────────────────────────── */}
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-4">
          <MetricCard
            icon={<Zap className="size-3.5" />}
            label="Attack Attempts"
            value={fmt(totalAttackAttempts)}
            sub="Persistent session attack records"
            variant={totalAttackAttempts > 0 ? "warning" : "muted"}
          />
          <MetricCard
            icon={<ShieldAlert className="size-3.5" />}
            label="Attacks Detected"
            value={fmt(totalAttacksDetected)}
            sub={
              detectionRate != null
                ? `${detectionRate}% detection rate`
                : "Confirmed by Isolation Forest"
            }
            variant={totalAttacksDetected > 0 ? "critical" : "muted"}
          />
          <MetricCard
            icon={<CheckCircle2 className="size-3.5" />}
            label="Terminated (success)"
            value={fmt(successfulTerminations)}
            sub="Confirmed process exit (return_code 0)"
            variant={successfulTerminations > 0 ? "success" : "muted"}
          />
          <MetricCard
            icon={<XCircle className="size-3.5" />}
            label="Terminated (failed)"
            value={fmt(failedTerminations)}
            sub="Non-zero exit code or process crash"
            variant={failedTerminations > 0 ? "critical" : "muted"}
          />
          <MetricCard
            icon={<AlertOctagon className="size-3.5" />}
            label="Normal Interruptions"
            value={fmt(normalTrafficInterruptions)}
            sub="Generator crashes only (manual stops excluded)"
            variant={normalTrafficInterruptions > 0 ? "critical" : "success"}
          />
          <MetricCard
            icon={<Clock className="size-3.5" />}
            label="Avg Response Latency"
            value={
              avgResponseLatencyMs != null
                ? `${fmt(avgResponseLatencyMs)} ms`
                : "—"
            }
            sub="First anomaly window to process termination"
            variant="info"
          />
          <MetricCard
            icon={<Radio className="size-3.5" />}
            label="Normal Frames (Attack)"
            badge="Estimated"
            value={fmt(estimatedNormalFramesDuringAttack)}
            sub="0x100 shared by RPM & Mode 1 flood"
            variant={estimatedNormalFramesDuringAttack > 0 ? "success" : "muted"}
          />
          <MetricCard
            icon={<Activity className="size-3.5" />}
            label="Normal Frames (Post-Mit)"
            badge="Estimated"
            value={fmt(estimatedNormalFramesAfterMitigation)}
            sub="Captured after attack simulator stopped"
            variant={estimatedNormalFramesAfterMitigation > 0 ? "success" : "muted"}
          />
          <MetricCard
            icon={<AlertTriangle className="size-3.5" />}
            label="Uncorrelated Windows"
            badge="Ground Truth: N/A"
            value={fmt(uncorrelatedAnomalyWindows)}
            sub="Anomaly window without confirmed incident"
            variant={uncorrelatedAnomalyWindows > 0 ? "warning" : "muted"}
          />
          <MetricCard
            icon={<Shield className="size-3.5" />}
            label="Recovery Verified"
            value={recoveryVerified ? "YES" : "NO"}
            sub={
              recoveryVerified
                ? `${verifiedNormalWindows} consecutive normal windows confirmed`
                : recoveryState === "ATTACK_STOPPED_VERIFYING"
                  ? `Verifying: ${verifiedNormalWindows} of 2 windows`
                  : "Awaiting attack termination"
            }
            variant={recoveryVerified ? "success" : "muted"}
          />
          <MetricCard
            icon={<Zap className="size-3.5" />}
            label="Mode 1 Attempts"
            value={fmt(mode1Stats.attempts)}
            sub={`${mode1Stats.detected} detected · ${mode1Stats.successfulTerminations} terminated`}
            variant={mode1Stats.attempts > 0 ? "warning" : "muted"}
          />
          <MetricCard
            icon={<Zap className="size-3.5" />}
            label="Mode 2 Attempts"
            value={fmt(mode2Stats.attempts)}
            sub={`${mode2Stats.detected} detected · ${mode2Stats.successfulTerminations} terminated`}
            variant={mode2Stats.attempts > 0 ? "warning" : "muted"}
          />
        </div>

        {/* ── Normal vs Malicious Traffic Over Time ────────────────────── */}
        <div className="rounded-lg border border-border/60 bg-card p-4">
          <div className="mb-3 flex items-center justify-between">
            <div>
              <h4 className="text-xs font-bold uppercase tracking-wider text-muted-foreground flex items-center gap-2">
                Estimated Normal vs Malicious CAN Traffic Over Time
                <span className="rounded border border-amber-500/30 bg-amber-500/10 px-1.5 py-0.5 font-mono text-[0.6rem] font-bold text-amber-400">
                  ESTIMATED · 0x100 Shared
                </span>
              </h4>
            </div>
            <span className="font-mono text-[0.65rem] text-muted-foreground">
              {trafficTimeSeries.length} windows · per-window frame breakdown
            </span>
          </div>
          <TrafficChart data={trafficTimeSeries} />
          <p className="mt-2 text-[0.65rem] text-muted-foreground">
            Notice: CAN arbitration ID 0x100 is emitted by both legitimate RPM generator and Mode 1 flood simulator.
            Bus-level frames cannot be separated with 100% cryptographic certainty without sender tagging; attribution during Mode 1 is an estimate based on nominal transmission rate. Mode 2 (0x999) frames are strictly malicious.
          </p>
        </div>

        {/* ── Detection & Termination Stats ────────────────────────────── */}
        <div className="rounded-lg border border-border/60 bg-card p-4">
          <h4 className="mb-4 text-xs font-bold uppercase tracking-wider text-muted-foreground">
            Attack Detection &amp; Termination Statistics
          </h4>

          {/* Detection funnel */}
          <div className="mb-4 space-y-2">
            {[
              {
                label: "Attack simulator processes started (History)",
                value: totalAttackAttempts,
                color: "bg-amber-500",
                icon: <Zap className="size-3" />,
              },
              {
                label: "Incidents confirmed by Isolation Forest",
                value: totalAttacksDetected,
                color: "bg-destructive",
                icon: <ShieldAlert className="size-3" />,
              },
              {
                label: "Confirmed terminated processes (rc=0)",
                value: successfulTerminations,
                color: "bg-emerald-500",
                icon: <CheckCircle2 className="size-3" />,
              },
              {
                label: "Termination failed (rc≠0 or crash)",
                value: failedTerminations,
                color: "bg-rose-700",
                icon: <XCircle className="size-3" />,
              },
            ].map(({ label, value, color, icon }) => {
              const max = Math.max(totalAttackAttempts, 1);
              const widthPct = (value / max) * 100;
              return (
                <div key={label} className="space-y-0.5">
                  <div className="flex items-center justify-between gap-2 text-[0.7rem]">
                    <span className="flex items-center gap-1 text-muted-foreground">
                      {icon} {label}
                    </span>
                    <span className="font-mono font-bold text-foreground">{value}</span>
                  </div>
                  <div className="h-1.5 overflow-hidden rounded-full bg-secondary">
                    <div
                      className={cn("h-full rounded-full transition-all", color)}
                      style={{ width: `${widthPct}%` }}
                    />
                  </div>
                </div>
              );
            })}
          </div>

          <p className="text-[0.65rem] text-muted-foreground">
            Strict process exit verification: an attack is only counted as successfully stopped after confirming the specific PID exited with return code 0 or clean signal.
          </p>
        </div>

        {/* ── Mode Comparison + Response Latency ───────────────────────── */}
        <div className="grid gap-4 md:grid-cols-2">
          <div className="rounded-lg border border-border/60 bg-card p-4">
            <div className="mb-3 flex items-center justify-between">
              <h4 className="text-xs font-bold uppercase tracking-wider text-muted-foreground">
                Attack Mode Comparison (Attributed by Record)
              </h4>
              <ShieldCheck className="size-4 text-muted-foreground/40" />
            </div>
            <ModeComparisonTable mode1={mode1Stats} mode2={mode2Stats} />
            <p className="mt-3 text-[0.65rem] text-muted-foreground">
              Mode 1 floods 0x100 at 1ms. Mode 2 injects extended ID 0x999 at 50ms.
              Statistics are attributed across all individual attack records in this session.
            </p>
          </div>

          <div className="rounded-lg border border-border/60 bg-card p-4">
            <div className="mb-3 flex items-center justify-between">
              <h4 className="text-xs font-bold uppercase tracking-wider text-muted-foreground">
                Response Latency (Milliseconds)
              </h4>
              <Clock className="size-4 text-muted-foreground/40" />
            </div>
            <LatencyChart points={latencyPoints} />
          </div>
        </div>

        {/* ── Successful vs Failed Response ────────────────────────────── */}
        <div className="rounded-lg border border-border/60 bg-card p-4">
          <div className="mb-4 flex items-center justify-between">
            <h4 className="text-xs font-bold uppercase tracking-wider text-muted-foreground">
              Successful vs Failed Termination Comparison
            </h4>
            <TrendingDown className="size-4 text-muted-foreground/40" />
          </div>
          <TerminationBar success={successfulTerminations} failed={failedTerminations} />
        </div>

        {/* ── Data Rigor & Ground Truth Notice ─────────────────────────── */}
        <div className="rounded-lg border border-border/40 bg-secondary/20 p-3">
          <p className="text-[0.65rem] leading-relaxed text-muted-foreground">
            <span className="font-semibold text-foreground">Data Measurement Status:</span>{" "}
            <span className="text-emerald-400 font-semibold">Measured:</span> Attack attempts, detections, process terminations, generator interruptions, and response latency (ms).{" "}
            <span className="text-amber-400 font-semibold">Estimated:</span> Normal vs malicious frame separation during concurrent Mode 1 (due to shared arbitration ID 0x100).{" "}
            <span className="text-rose-400 font-semibold">Unavailable:</span> False-positive count (the virtual CAN interface lacks ground-truth ECU attestation).
          </p>
        </div>
      </div>
    </Panel>
  );
}
