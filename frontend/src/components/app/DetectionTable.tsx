import { useState } from "react";

import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { cn } from "@/lib/utils";
import { FEATURE_COLUMNS, type FrequencyRow, type InferenceWindow } from "@/lib/api/schemas";
import { fmtTime, Verdict } from "./primitives";

const th = "sticky top-0 z-10 border-b bg-card px-3 py-2.5 text-left font-mono text-[0.62rem] font-semibold uppercase tracking-[0.12em] text-muted-foreground";
const td = "px-3 py-2 font-mono text-xs tabular-nums";

export function DetectionTable({ windows, newestFirst = false, maxHeight = 520 }: { windows: InferenceWindow[]; newestFirst?: boolean; maxHeight?: number }) {
  const [selected, setSelected] = useState<InferenceWindow | null>(null);
  const rows = newestFirst ? [...windows].reverse() : windows;
  return (
    <>
      <div className="overflow-auto rounded-xl border" style={{ maxHeight }}>
        <table className="w-full min-w-[720px] border-collapse">
          <thead>
            <tr>
              {["Win #", "Start time (UTC)", "Prediction", "Frames", "Unique IDs", "Extended", "Anomaly score"].map((h) => (
                <th key={h} className={th}>
                  {h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {rows.map((w) => {
              const anomaly = w.prediction === "ANOMALY";
              return (
                <tr
                  key={w.window_index}
                  onClick={() => setSelected(w)}
                  className={cn(
                    "cursor-pointer border-b transition-colors last:border-0 hover:bg-secondary/60",
                    anomaly && "bg-destructive/[0.06]",
                  )}
                >
                  <td className={td}>{w.window_index}</td>
                  <td className={cn(td, "text-muted-foreground")}>{fmtTime(w.window_start_utc)}</td>
                  <td className={td}>
                    <Verdict prediction={w.prediction} />
                  </td>
                  <td className={td}>{w.features.total_frames}</td>
                  <td className={td}>{w.features.unique_can_ids}</td>
                  <td className={td}>{w.features.extended_frame_count}</td>
                  <td className={cn(td, anomaly && "font-semibold text-destructive")}>
                    <div className="flex items-center gap-2">
                      <span className="w-16">{w.anomaly_score.toFixed(5)}</span>
                      <span className="h-1 w-16 overflow-hidden rounded-full bg-secondary">
                        <span
                          className={cn("block h-full rounded-full", anomaly ? "bg-destructive" : "bg-primary")}
                          style={{ width: `${Math.min(100, w.anomaly_score * 100)}%` }}
                        />
                      </span>
                    </div>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
      <Sheet open={!!selected} onOpenChange={(o) => !o && setSelected(null)}>
        <SheetContent className="w-full overflow-y-auto sm:max-w-md">
          {selected && (
            <>
              <SheetHeader>
                <SheetTitle className="flex items-center gap-3">
                  Window #{selected.window_index} <Verdict prediction={selected.prediction} />
                </SheetTitle>
                <SheetDescription className="font-mono text-xs">{fmtTime(selected.window_start_utc)} UTC · 1000 ms</SheetDescription>
              </SheetHeader>
              <div className="mt-6 rounded-xl border bg-secondary/40 p-4">
                <div className="eyebrow">Anomaly score</div>
                <div className={cn("mt-1 font-display text-3xl font-semibold", selected.prediction === "ANOMALY" && "text-destructive")}>
                  {selected.anomaly_score.toFixed(5)}
                </div>
                <p className="mt-1 text-xs text-muted-foreground">Higher means more unusual to the saved Isolation Forest model.</p>
              </div>
              {selected.prediction === "ANOMALY" && (
                <section className="mt-6 rounded-xl border border-destructive/30 bg-destructive/[0.04] p-4">
                  <div className="flex items-center justify-between gap-3">
                    <div className="eyebrow">Alert explanation</div>
                    {selected.explanation && (
                      <span className="rounded-md border px-2 py-1 font-mono text-[0.65rem] font-semibold">
                        {selected.explanation.severity}
                      </span>
                    )}
                  </div>

                  {selected.explanation ? (
                    <>
                      <p className="mt-2 text-sm leading-relaxed">
                        {selected.explanation.summary}
                      </p>

                      {selected.explanation.reasons.length > 0 ? (
                        <ul className="mt-3 space-y-3">
                          {selected.explanation.reasons.map((reason) => (
                            <li key={reason.code} className="border-t pt-3">
                              <div className="font-mono text-xs font-semibold">
                                {reason.code}
                              </div>
                              <p className="mt-1 text-xs text-muted-foreground">
                                {reason.message}
                              </p>
                              <dl className="mt-2 space-y-1">
                                {Object.entries(reason.evidence).map(([key, value]) => (
                                  <div key={key} className="flex justify-between gap-3 font-mono text-[0.68rem]">
                                    <dt className="text-muted-foreground">{key}</dt>
                                    <dd>{String(value)}</dd>
                                  </div>
                                ))}
                              </dl>
                            </li>
                          ))}
                        </ul>
                      ) : (
                        <p className="mt-2 text-xs text-muted-foreground">
                          No specific explanation rule matched this anomaly.
                        </p>
                      )}
                    </>
                  ) : (
                    <p className="mt-2 text-xs text-muted-foreground">
                      Explanation unavailable for this demo or older result.
                    </p>
                  )}
                  <p className="mt-3 text-[0.68rem] text-muted-foreground">
                    Heuristic evidence only; an anomaly does not prove vehicle compromise.
                  </p>
                </section>
              )}

              <div className="eyebrow mb-2 mt-6">Model feature vector</div>
              <dl className="divide-y rounded-xl border">
                {FEATURE_COLUMNS.map((c) => (
                  <div key={c} className="flex justify-between px-3 py-2 font-mono text-xs">
                    <dt className="text-muted-foreground">{c}</dt>
                    <dd className="tabular-nums">{selected.features[c]}</dd>
                  </div>
                ))}
              </dl>
            </>
          )}
        </SheetContent>
      </Sheet>
    </>
  );
}

export function FrequencyTable({ rows }: { rows: FrequencyRow[] }) {
  const f = (v: number | null) => (v === null ? "N/A" : v.toFixed(3));
  return (
    <div className="overflow-auto rounded-xl border">
      <table className="w-full min-w-[820px] border-collapse">
        <thead>
          <tr>
            {["CAN ID", "Format", "Frames", "% of total", "Unique payloads", "Mean gap ms", "Median ms", "Min ms", "Max ms"].map((h) => (
              <th key={h} className={th}>
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => (
            <tr key={r.can_id} className="border-b last:border-0">
              <td className={cn(td, "font-semibold text-primary")}>{r.can_id}</td>
              <td className={td}>{r.frame_format}</td>
              <td className={td}>{r.frame_count.toLocaleString()}</td>
              <td className={td}>{r.percentage_of_total.toFixed(2)}</td>
              <td className={td}>{r.unique_payload_count}</td>
              <td className={td}>{f(r.mean_interarrival_ms)}</td>
              <td className={td}>{f(r.median_interarrival_ms)}</td>
              <td className={td}>{f(r.min_interarrival_ms)}</td>
              <td className={td}>{f(r.max_interarrival_ms)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
