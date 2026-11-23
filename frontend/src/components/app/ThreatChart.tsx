import { Area, CartesianGrid, ComposedChart, Line, ResponsiveContainer, Scatter, Tooltip, XAxis, YAxis } from "recharts";

import type { InferenceWindow } from "@/lib/api/schemas";

export function ThreatChart({ windows, height = 320 }: { windows: InferenceWindow[]; height?: number }) {
  const data = windows.map((w) => ({
    window: w.window_index,
    score: w.anomaly_score,
    anomaly: w.prediction === "ANOMALY" ? w.anomaly_score : null,
  }));
  return (
    <div style={{ height }} className="w-full">
      <ResponsiveContainer width="100%" height="100%">
        <ComposedChart data={data} margin={{ top: 10, right: 12, bottom: 0, left: -18 }}>
          <defs>
            <linearGradient id="threat-fill" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="var(--primary)" stopOpacity={0.35} />
              <stop offset="100%" stopColor="var(--primary)" stopOpacity={0} />
            </linearGradient>
          </defs>
          <CartesianGrid stroke="var(--border)" vertical={false} />
          <XAxis dataKey="window" tick={{ fontSize: 11, fill: "var(--muted-foreground)" }} stroke="var(--border)" tickLine={false} />
          <YAxis domain={[0.2, 1]} tick={{ fontSize: 11, fill: "var(--muted-foreground)" }} stroke="var(--border)" tickLine={false} />
          <Tooltip
            cursor={{ stroke: "var(--primary)", strokeOpacity: 0.3 }}
            contentStyle={{ background: "var(--popover)", border: "1px solid var(--border)", borderRadius: 10, fontSize: 12, color: "var(--foreground)" }}
            formatter={(v: number, k) => [Number(v).toFixed(5), k === "anomaly" ? "anomalous window" : "anomaly score"]}
            labelFormatter={(l) => `Window #${l}`}
          />
          <Area type="linear" dataKey="score" stroke="none" fill="url(#threat-fill)" isAnimationActive={false} />
          <Line type="linear" dataKey="score" stroke="var(--primary)" strokeWidth={2} dot={false} isAnimationActive={false} />
          <Scatter dataKey="anomaly" fill="var(--destructive)" isAnimationActive={false} />
        </ComposedChart>
      </ResponsiveContainer>
    </div>
  );
}
