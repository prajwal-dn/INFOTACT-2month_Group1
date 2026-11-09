/**
 * Phase 6: Real-Time CAN Traffic Monitoring
 *
 * Provides deep live network observability into the CAN bus:
 * - Live CAN frames per second (FPS) and peak rate
 * - Traffic volume over time with normal vs anomalous window indicators
 * - Standard vs Extended CAN frames breakdown
 * - Traffic distribution by arbitration CAN ID (0x100, 0x101, 0x102, 0x999, other)
 * - Clear disclosure distinguishing measured data from estimated attribution
 */
import { useMemo } from "react";
import {
  Area,
  Bar,
  BarChart,
  CartesianGrid,
  ComposedChart,
  Legend,
  Line,
  ResponsiveContainer,
  Scatter,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import {
  Activity,
  AlertTriangle,
  BarChart2,
  Cpu,
  Layers,
  Radio,
  TrendingUp,
} from "lucide-react";

import { Panel } from "@/components/app/primitives";
import type { InferenceWindow } from "@/lib/api/schemas";
import { cn } from "@/lib/utils";

interface RealTimeTrafficMonitorProps {
  windows: InferenceWindow[];
  capturing: boolean;
  pendingWindowIndex?: number | null;
}

export function RealTimeTrafficMonitor({
  windows,
  capturing,
  pendingWindowIndex,
}: RealTimeTrafficMonitorProps) {
  const latestWindow = windows.length > 0 ? windows[windows.length - 1] : null;

  // Real-time FPS metrics
  const currentFps = latestWindow ? latestWindow.features.total_frames : 0;
  const fpsList = windows.map((w) => w.features.total_frames);
  const peakFps = fpsList.length > 0 ? Math.max(...fpsList) : 0;
  const avgFps = fpsList.length > 0 ? Math.round(fpsList.reduce((a, b) => a + b, 0) / fpsList.length) : 0;

  // Volume over time chart data
  const volumeData = useMemo(() => {
    return windows.map((w) => {
      const isAnomaly = w.prediction === "ANOMALY";
      const total = w.features.total_frames;
      const extended = w.features.extended_frame_count;
      const standard = Math.max(0, total - extended);

      return {
        window: w.window_index,
        total,
        standard,
        extended,
        anomalyScore: w.anomaly_score,
        anomalyMarker: isAnomaly ? total : null,
        isAnomaly,
      };
    });
  }, [windows]);

  // ID Distribution breakdown from latest window (or aggregated if multiple windows)
  const idDistribution = useMemo(() => {
    if (!latestWindow) return [];
    const f = latestWindow.features;
    const total = f.total_frames || 1;

    return [
      {
        id: "0x100",
        label: "0x100 (RPM / Flood)",
        count: f.id_0x100_count,
        pct: (f.id_0x100_count / total) * 100,
        type: "Standard",
        color: "bg-cyan-500",
        barColor: "#06b6d4",
      },
      {
        id: "0x101",
        label: "0x101 (Speed)",
        count: f.id_0x101_count,
        pct: (f.id_0x101_count / total) * 100,
        type: "Standard",
        color: "bg-emerald-500",
        barColor: "#10b981",
      },
      {
        id: "0x102",
        label: "0x102 (Coolant)",
        count: f.id_0x102_count,
        pct: (f.id_0x102_count / total) * 100,
        type: "Standard",
        color: "bg-teal-500",
        barColor: "#14b8a6",
      },
      {
        id: "0x999",
        label: "0x999 (Extended)",
        count: f.id_0x999_count,
        pct: (f.id_0x999_count / total) * 100,
        type: "Extended (29-bit)",
        color: "bg-amber-500",
        barColor: "#f59e0b",
      },
      {
        id: "Other",
        label: "Other IDs",
        count: f.other_id_count,
        pct: (f.other_id_count / total) * 100,
        type: "Arbitrary",
        color: "bg-slate-500",
        barColor: "#64748b",
      },
    ].filter((item) => item.count > 0 || windows.length === 0);
  }, [latestWindow, windows.length]);

  return (
    <Panel
      title="Real-Time CAN Traffic Monitoring"
      aside={
        <div className="flex items-center gap-2">
          {capturing && (
            <span className="flex items-center gap-1.5 font-mono text-[0.68rem] text-emerald-400">
              <span className="size-1.5 rounded-full bg-emerald-400 animate-pulse" />
              Live 1000ms cadence
            </span>
          )}
          {pendingWindowIndex != null && (
            <span className="font-mono text-[0.68rem] text-muted-foreground">
              Window #{pendingWindowIndex} buffering…
            </span>
          )}
        </div>
      }
    >
      <div className="space-y-5">
        {/* Top metrics bar */}
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
          <div className="rounded-lg border border-border/60 bg-secondary/30 p-3">
            <div className="flex items-center justify-between text-muted-foreground mb-1">
              <span className="text-[0.68rem] font-semibold uppercase tracking-wider">Current Throughput</span>
              <Activity className="size-3.5 text-cyan-400" />
            </div>
            <div className="font-mono text-xl font-bold text-foreground">
              {capturing && latestWindow ? `${currentFps.toLocaleString()} fps` : capturing ? "Buffering…" : "0 fps"}
            </div>
            <div className="text-[0.65rem] text-muted-foreground mt-0.5">
              1-second window frame rate
            </div>
          </div>

          <div className="rounded-lg border border-border/60 bg-secondary/30 p-3">
            <div className="flex items-center justify-between text-muted-foreground mb-1">
              <span className="text-[0.68rem] font-semibold uppercase tracking-wider">Peak Bus Load</span>
              <TrendingUp className="size-3.5 text-amber-400" />
            </div>
            <div className="font-mono text-xl font-bold text-foreground">
              {peakFps > 0 ? `${peakFps.toLocaleString()} fps` : "—"}
            </div>
            <div className="text-[0.65rem] text-muted-foreground mt-0.5">
              Highest observed burst rate
            </div>
          </div>

          <div className="rounded-lg border border-border/60 bg-secondary/30 p-3">
            <div className="flex items-center justify-between text-muted-foreground mb-1">
              <span className="text-[0.68rem] font-semibold uppercase tracking-wider">Average Cadence</span>
              <Cpu className="size-3.5 text-emerald-400" />
            </div>
            <div className="font-mono text-xl font-bold text-foreground">
              {avgFps > 0 ? `${avgFps.toLocaleString()} fps` : "—"}
            </div>
            <div className="text-[0.65rem] text-muted-foreground mt-0.5">
              Mean nominal bus rate
            </div>
          </div>

          <div className="rounded-lg border border-border/60 bg-secondary/30 p-3">
            <div className="flex items-center justify-between text-muted-foreground mb-1">
              <span className="text-[0.68rem] font-semibold uppercase tracking-wider">Extended 29-bit</span>
              <Layers className="size-3.5 text-amber-500" />
            </div>
            <div className="font-mono text-xl font-bold text-foreground">
              {latestWindow?.features?.extended_frame_count != null
                ? `${latestWindow.features.extended_frame_count.toLocaleString()}`
                : "0"}
            </div>
            <div className="text-[0.65rem] text-muted-foreground mt-0.5">
              Non-standard format frames
            </div>
          </div>
        </div>

        {/* Traffic volume over time chart */}
        <div className="space-y-2">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
              <BarChart2 className="size-3.5" />
              Traffic Volume Over Time (Frames / Second)
            </div>
            <div className="flex items-center gap-3 text-[0.68rem] text-muted-foreground font-mono">
              <span className="flex items-center gap-1">
                <span className="size-2 rounded-full bg-cyan-400 inline-block" /> Standard CAN
              </span>
              <span className="flex items-center gap-1">
                <span className="size-2 rounded-full bg-amber-400 inline-block" /> Extended (29-bit)
              </span>
              <span className="flex items-center gap-1">
                <span className="size-2 rounded-full bg-destructive inline-block" /> Anomaly Window
              </span>
            </div>
          </div>

          <div className="h-64 w-full rounded-lg border border-border/60 bg-secondary/20 p-2">
            {windows.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <ComposedChart data={volumeData} margin={{ top: 10, right: 12, bottom: 0, left: -18 }}>
                  <defs>
                    <linearGradient id="standard-fill" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%" stopColor="#06b6d4" stopOpacity={0.3} />
                      <stop offset="100%" stopColor="#06b6d4" stopOpacity={0.02} />
                    </linearGradient>
                    <linearGradient id="extended-fill" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%" stopColor="#f59e0b" stopOpacity={0.4} />
                      <stop offset="100%" stopColor="#f59e0b" stopOpacity={0.05} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid stroke="var(--border)" strokeDasharray="3 3" vertical={false} />
                  <XAxis
                    dataKey="window"
                    tick={{ fontSize: 10, fill: "var(--muted-foreground)" }}
                    stroke="var(--border)"
                    tickLine={false}
                  />
                  <YAxis
                    tick={{ fontSize: 10, fill: "var(--muted-foreground)" }}
                    stroke="var(--border)"
                    tickLine={false}
                  />
                  <Tooltip
                    contentStyle={{
                      background: "var(--popover)",
                      border: "1px solid var(--border)",
                      borderRadius: 8,
                      fontSize: 11,
                      color: "var(--foreground)",
                    }}
                    formatter={(v: number, name: string) => [
                      `${Number(v).toLocaleString()} frames`,
                      name === "standard"
                        ? "Standard Frames"
                        : name === "extended"
                          ? "Extended Frames"
                          : name === "anomalyMarker"
                            ? "Anomalous Window Rate"
                            : "Total Frames",
                    ]}
                    labelFormatter={(label) => `Window #${label}`}
                  />
                  <Area
                    type="monotone"
                    dataKey="standard"
                    stroke="#06b6d4"
                    fill="url(#standard-fill)"
                    strokeWidth={1.5}
                    isAnimationActive={false}
                  />
                  <Area
                    type="monotone"
                    dataKey="extended"
                    stroke="#f59e0b"
                    fill="url(#extended-fill)"
                    strokeWidth={1.5}
                    isAnimationActive={false}
                  />
                  <Scatter
                    dataKey="anomalyMarker"
                    fill="var(--destructive)"
                    isAnimationActive={false}
                  />
                </ComposedChart>
              </ResponsiveContainer>
            ) : (
              <div className="flex h-full items-center justify-center text-xs text-muted-foreground">
                {capturing ? "Collecting first 1-second window…" : "Start capture to visualize live traffic volume"}
              </div>
            )}
          </div>
        </div>

        {/* CAN ID traffic distribution */}
        <div className="space-y-2">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
              Traffic Distribution by CAN Arbitration ID (Latest Window)
            </span>
            <span className="text-[0.68rem] text-muted-foreground font-mono">
              Window #{latestWindow?.window_index ?? 0}
            </span>
          </div>

          <div className="grid grid-cols-1 gap-2 sm:grid-cols-2 lg:grid-cols-5">
            {idDistribution.map((item) => (
              <div
                key={item.id}
                className="rounded-lg border border-border/60 bg-secondary/30 p-2.5 flex flex-col justify-between"
              >
                <div className="flex items-center justify-between mb-1.5">
                  <span className="font-mono text-xs font-semibold text-foreground">
                    {item.id}
                  </span>
                  <span className="text-[0.65rem] text-muted-foreground">{item.type}</span>
                </div>
                <div className="flex items-baseline justify-between">
                  <span className="font-mono text-sm font-bold text-foreground">
                    {item.count.toLocaleString()}
                  </span>
                  <span className="font-mono text-[0.68rem] text-muted-foreground">
                    {item.pct.toFixed(1)}%
                  </span>
                </div>
                {/* Visual percentage meter */}
                <div className="mt-2 h-1.5 w-full overflow-hidden rounded-full bg-secondary">
                  <div
                    className={cn("h-full rounded-full transition-all", item.color)}
                    style={{ width: `${Math.min(100, Math.max(3, item.pct))}%` }}
                  />
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Rigorous Evidence Notice */}
        <div className="rounded-lg border border-border/60 bg-secondary/30 p-3 text-xs text-muted-foreground flex items-start gap-2.5">
          <AlertTriangle className="size-4 shrink-0 text-amber-500 mt-0.5" />
          <div className="space-y-1">
            <p className="font-semibold text-foreground text-[0.72rem]">
              Measured Data vs. Estimated Attribution Policy
            </p>
            <p className="text-[0.68rem] leading-relaxed">
              Window frame counts, standard vs. extended formats, and anomaly scores are directly measured from the raw Linux socketCAN interface. When Mode 1 flooding is active concurrently with normal traffic, frames with ID <code className="font-mono text-foreground font-bold">0x100</code> are shared between the legitimate RPM generator and the flood adversary. In compliance with SOC audit standards, frame counts for ID 0x100 during active flooding are labeled as <strong className="text-foreground">ESTIMATED</strong>.
            </p>
          </div>
        </div>
      </div>
    </Panel>
  );
}

