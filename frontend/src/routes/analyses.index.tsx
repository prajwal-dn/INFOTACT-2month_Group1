import { createFileRoute, Link } from "@tanstack/react-router";
import { FileSearch } from "lucide-react";

import { Button } from "@/components/ui/button";
import { DemoBadge } from "@/components/app/DemoNotice";
import { EmptyState, ErrorState, fmtAgo, PageHeader } from "@/components/app/primitives";
import { useAnalyses } from "@/lib/api/queries";
import { pageHead } from "@/lib/head";
import { cn } from "@/lib/utils";

export const Route = createFileRoute("/analyses/")({
  head: () => pageHead("Analyses", "History of saved-capture and live-capture inference runs."),
  component: Analyses,
});

const ORIGIN: Record<string, string> = { preset: "Preset", path: "Backend path", upload: "Upload", live: "Live capture" };

function Analyses() {
  const q = useAnalyses();
  return (
    <div>
      <PageHeader
        eyebrow="History"
        title="Analyses"
        description="Every inference run returned by the backend."
        actions={
          <Button asChild variant="signal">
            <Link to="/analyze">
              <FileSearch /> New analysis
            </Link>
          </Button>
        }
      />
      {q.isError && <ErrorState error={q.error} />}
      {q.isLoading && <div className="h-64 animate-pulse rounded-2xl bg-secondary/40" />}
      {q.data && !q.data.length && <EmptyState title="No analyses yet">Run one from Analyze capture or the live monitor.</EmptyState>}
      {!!q.data?.length && (
        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
          {q.data.map((a) => {
            const rate = a.windows_scored ? (a.anomaly_count / a.windows_scored) * 100 : 0;
            return (
              <Link
                key={a.id}
                to="/analyses/$analysisId"
                params={{ analysisId: a.id }}
                className={cn("surface group block p-5 transition-all hover:-translate-y-0.5 hover:glow-primary", a.anomaly_count > 0 && "border-destructive/30")}
              >
                <div className="flex items-center justify-between gap-2">
                  <span className="eyebrow">{ORIGIN[a.origin]}</span>
                  <DemoBadge source={a.data_source} />
                </div>
                <div className="mt-3 truncate font-mono text-sm font-medium">{a.capture_file}</div>
                <div className="mt-1 text-xs text-muted-foreground">{fmtAgo(a.created_at)} · {a.frames_loaded.toLocaleString()} frames</div>
                <div className="mt-5 flex items-end justify-between">
                  <div>
                    <div className={cn("font-display text-3xl font-semibold", a.anomaly_count ? "text-destructive" : "text-success")}>
                      {a.anomaly_count}
                      <span className="text-base text-muted-foreground"> / {a.windows_scored}</span>
                    </div>
                    <div className="text-xs text-muted-foreground">anomalous windows</div>
                  </div>
                  <div className="font-mono text-xs text-muted-foreground">{rate.toFixed(1)}%</div>
                </div>
                <div className="mt-3 h-1 overflow-hidden rounded-full bg-secondary">
                  <div className={cn("h-full rounded-full", a.anomaly_count ? "bg-destructive" : "bg-success")} style={{ width: `${Math.max(rate, a.anomaly_count ? 3 : 100)}%` }} />
                </div>
              </Link>
            );
          })}
        </div>
      )}
    </div>
  );
}
