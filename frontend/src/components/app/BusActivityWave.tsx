// Per-second CAN bus activity waveform. Purely a visualisation of windows the
// Python backend returned: bar height = total_frames, colour = backend
// `prediction`. No detection or thresholding happens here.
import { useState } from "react";
import { Activity } from "lucide-react";

import { DemoBadge } from "@/components/app/DemoNotice";
import type { DataSource, InferenceWindow } from "@/lib/api/schemas";
import { cn } from "@/lib/utils";

export type WaveSource =
  | { kind: "live"; windows: InferenceWindow[]; pendingWindowIndex: number | null; dataSource: DataSource; capturing: boolean }
  | { kind: "analysis"; windows: InferenceWindow[]; excludedPartialWindow: number | null; dataSource: DataSource; label?: string }
  | { kind: "idle" };

type Slot = { kind: "scored"; w: InferenceWindow } | { kind: "pending"; index: number };

export function BusActivityWave({ source, maxBars = 60, height = 96, className }: { source: WaveSource; maxBars?: number; height?: number; className?: string }) {
  const [hover, setHover] = useState<number | null>(null);

  if (source.kind === "idle") {
    return (
      <div data-testid="bus-wave-idle" className="rounded-xl border border-dashed px-4 py-3">
        <div className="flex items-center justify-between font-mono text-[0.65rem] uppercase tracking-[0.14em] text-muted-foreground">
          <span className="flex items-center gap-1.5">
            <Activity className="size-3.5" /> Bus activity · idle
          </span>
          <span>no capture loaded</span>
        </div>
        <div className="relative mt-3 flex items-end gap-[3px]" style={{ height: height - 40 }} aria-hidden>
          {Array.from({ length: 40 }, (_, i) => (
            <div key={i} className="h-[2px] flex-1 rounded-full bg-border" />
          ))}
        </div>
        <p className="mt-2 text-xs text-muted-foreground">Start a live capture or analyze a capture to see real per-second traffic here.</p>
      </div>
    );
  }

  const windows = [...source.windows].sort((a, b) => a.window_index - b.window_index);
  const slots: Slot[] = windows.map((w) => ({ kind: "scored", w }));
  if (source.kind === "live" && source.capturing && source.pendingWindowIndex != null && !windows.some((w) => w.window_index === source.pendingWindowIndex)) {
    slots.push({ kind: "pending", index: source.pendingWindowIndex });
  }
  const visible = slots.slice(-maxBars);
  const peak = Math.max(1, ...windows.map((w) => w.features.total_frames));
  const anomalies = windows.filter((w) => w.prediction === "ANOMALY").length;
  const hovered = hover != null ? visible[hover] : undefined;
  const barArea = height - 40;

  return (
    <div data-testid="bus-wave" data-source={source.dataSource} className={cn("rounded-xl border bg-background/40 px-4 py-3", className)}>
      <div className="flex flex-wrap items-center justify-between gap-2 font-mono text-[0.65rem] uppercase tracking-[0.14em] text-muted-foreground">
        <span className="flex items-center gap-1.5">
          <Activity className={cn("size-3.5", source.kind === "live" && source.capturing && "text-primary animate-pulse")} />
          {source.kind === "live" ? (source.capturing ? "Live · frames / second" : "Live session · frames / second") : `${source.label ?? "Latest analysis"} · frames / second`}
          <DemoBadge source={source.dataSource} />
        </span>
        <span>
          {windows.length} scored · <span className={anomalies ? "text-destructive" : undefined}>{anomalies} anomaly</span>
          {source.kind === "analysis" && source.excludedPartialWindow != null && ` · #${source.excludedPartialWindow} partial, excluded`}
        </span>
      </div>

      {visible.length === 0 ? (
        <div className="flex items-center justify-center text-xs text-muted-foreground" style={{ height: barArea + 12 }}>
          Waiting for the first completed one-second window…
        </div>
      ) : (
        <div className="relative mt-3" onMouseLeave={() => setHover(null)}>
          <div className="flex items-end gap-[3px]" style={{ height: barArea }} role="img" aria-label={`CAN bus activity, ${windows.length} windows, ${anomalies} anomalous`}>
            {visible.map((slot, i) => {
              if (slot.kind === "pending") {
                return (
                  <div
                    key={`p${slot.index}`}
                    data-testid="bus-wave-pending"
                    onMouseEnter={() => setHover(i)}
                    className="h-full flex-1 animate-pulse rounded-sm border border-dashed border-primary/60 bg-transparent"
                    style={{ maxWidth: 14 }}
                  />
                );
              }
              const w = slot.w;
              const anomaly = w.prediction === "ANOMALY";
              const injected = w.features.id_0x999_count > 0;
              const pct = Math.max(4, (w.features.total_frames / peak) * 100);
              return (
                <div
                  key={w.window_index}
                  data-testid="bus-wave-bar"
                  data-prediction={w.prediction}
                  data-0x999={injected ? w.features.id_0x999_count : undefined}
                  onMouseEnter={() => setHover(i)}
                  className="relative flex h-full flex-1 items-end"
                  style={{ maxWidth: 14 }}
                >
                  {injected && <span className="absolute left-1/2 top-0 size-1.5 -translate-x-1/2 rounded-full bg-warning" />}
                  <div
                    className={cn(
                      "w-full rounded-sm transition-[height] duration-500",
                      anomaly ? "bg-destructive" : "bg-primary/70",
                      injected && "ring-1 ring-warning",
                      hover === i && "brightness-125",
                    )}
                    style={{ height: `${pct}%` }}
                  />
                </div>
              );
            })}
          </div>
          <div className="mt-1 h-px bg-border" />

          {hovered && (
            <div className="pointer-events-none absolute -top-2 right-0 z-10 -translate-y-full rounded-lg border bg-popover px-3 py-2 font-mono text-[0.7rem] text-popover-foreground shadow-lg" data-testid="bus-wave-tooltip">
              {hovered.kind === "pending" ? (
                <>
                  <div className="font-semibold">Window #{hovered.index} · pending</div>
                  <div className="text-muted-foreground">Still collecting frames — not scored yet</div>
                </>
              ) : (
                <>
                  <div className="flex items-center gap-2 font-semibold">
                    Window #{hovered.w.window_index}
                    <span className={hovered.w.prediction === "ANOMALY" ? "text-destructive" : "text-success"}>{hovered.w.prediction}</span>
                  </div>
                  <div className="text-muted-foreground">{hovered.w.window_start_utc}</div>
                  <div>anomaly score {hovered.w.anomaly_score.toFixed(4)}</div>
                  <div>{hovered.w.features.total_frames} frames · {hovered.w.features.unique_can_ids} IDs</div>
                  <div>max ID share {hovered.w.features.max_id_share_pct.toFixed(1)}%</div>
                  <div className={hovered.w.features.id_0x999_count ? "text-warning" : undefined}>0x999 frames {hovered.w.features.id_0x999_count}</div>
                </>
              )}
            </div>
          )}
        </div>
      )}

      <div className="mt-2 flex flex-wrap gap-3 text-[0.65rem] text-muted-foreground">
        <span className="flex items-center gap-1"><i className="size-2 rounded-sm bg-primary/70" /> NORMAL</span>
        <span className="flex items-center gap-1"><i className="size-2 rounded-sm bg-destructive" /> ANOMALY</span>
        <span className="flex items-center gap-1"><i className="size-1.5 rounded-full bg-warning" /> has 0x999 frames</span>
        {source.kind === "live" && <span className="flex items-center gap-1"><i className="size-2 rounded-sm border border-dashed border-primary/60" /> pending, unscored</span>}
        <span className="ml-auto">{source.dataSource === "backend" ? "Verdicts from the Python Isolation Forest model" : "Illustrative demo predictions"}</span>
      </div>
    </div>
  );
}
