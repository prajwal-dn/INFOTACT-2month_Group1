import { Activity, CheckCircle2, Gauge, ShieldAlert } from "lucide-react";
import type { ReactNode } from "react";

import { cn } from "@/lib/utils";

function Metric({ label, value, sub, icon, accent, alert }: { label: string; value: string; sub?: string; icon: ReactNode; accent: string; alert?: boolean }) {
  return (
    <div className={cn("surface relative overflow-hidden p-5 animate-rise", alert && "surface-alert")}>
      <div className={cn("absolute inset-x-0 top-0 h-px", accent)} />
      <div className="flex items-center justify-between">
        <span className="eyebrow">{label}</span>
        <span className="text-muted-foreground [&_svg]:size-4">{icon}</span>
      </div>
      <div className="mt-3 font-display text-4xl font-semibold tabular-nums tracking-tight">{value}</div>
      {sub && <div className="mt-1 text-xs text-muted-foreground">{sub}</div>}
    </div>
  );
}

export function MetricGrid({ metrics }: { metrics: { total: number; normal: number; anomalies: number; rate: number } | null }) {
  const v = (n: number | undefined) => (metrics && n !== undefined ? n.toLocaleString() : "—");
  return (
    <div className="grid grid-cols-2 gap-4 xl:grid-cols-4">
      <Metric label="Windows scored" value={v(metrics?.total)} sub="1-second feature windows" icon={<Activity />} accent="bg-primary" />
      <Metric label="Normal windows" value={v(metrics?.normal)} sub="Classified NORMAL" icon={<CheckCircle2 />} accent="bg-success" />
      <Metric
        label="Anomalies detected"
        value={v(metrics?.anomalies)}
        sub="Classified ANOMALY"
        icon={<ShieldAlert />}
        accent="bg-destructive"
        alert={!!metrics?.anomalies}
      />
      <Metric label="Anomaly rate" value={metrics ? `${metrics.rate.toFixed(1)}%` : "—"} sub="Of scored windows" icon={<Gauge />} accent="bg-warning" />
    </div>
  );
}
