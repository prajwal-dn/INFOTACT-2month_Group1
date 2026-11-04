import { createFileRoute, Link } from "@tanstack/react-router";
import { ArrowRight, FileSearch, Radio, ShieldAlert } from "lucide-react";

import { Button } from "@/components/ui/button";
import { DemoBadge } from "@/components/app/DemoNotice";
import { MetricGrid } from "@/components/app/MetricGrid";
import { EmptyState, ErrorState, fmtAgo, Panel } from "@/components/app/primitives";
import { SystemChecks } from "@/components/app/SystemChecks";
import { ThreatChart } from "@/components/app/ThreatChart";
import { BusActivityWave, type WaveSource } from "@/components/app/BusActivityWave";
import { useActiveLiveSessionId } from "@/lib/live-session-store";
import { useAuditLog } from "@/lib/audit-log";
import { metricsOf, useAnalyses, useAnalysis, useLiveSession, useStatus } from "@/lib/api/queries";
import { pageHead } from "@/lib/head";
import { cn } from "@/lib/utils";

export const Route = createFileRoute("/")({
  head: () => pageHead("Overview", "Status of the virtual CAN capture pipeline and the latest Isolation Forest detection results."),
  component: Overview,
});

function Overview() {
  const status = useStatus();
  const analyses = useAnalyses();
  const latestId = analyses.data?.[0]?.id;
  const latest = useAnalysis(latestId);
  const log = useAuditLog();
  const alerts = log.filter((e) => e.level === "ALERT").slice(0, 5);
  const liveId = useActiveLiveSessionId();
  const live = useLiveSession(liveId, true);
  const waveSource: WaveSource = live.data
    ? { kind: "live", windows: live.data.windows, pendingWindowIndex: live.data.pending_window_index, dataSource: live.data.data_source, capturing: live.data.state === "capturing" }
    : latest.data
      ? { kind: "analysis", windows: latest.data.windows, excludedPartialWindow: latest.data.excluded_partial_window, dataSource: latest.data.data_source, label: latest.data.capture_file }
      : { kind: "idle" };

  return (
    <div className="space-y-6">
      <section className="surface grid-lines relative overflow-hidden p-6 md:p-8 animate-rise">
        <div className="grid gap-8 lg:grid-cols-[1.4fr_1fr]">
          <div>
            <div className="eyebrow mb-3 flex items-center gap-2">
              Detection console <DemoBadge />
            </div>
            <h1 className="max-w-xl text-4xl font-semibold leading-[1.08] md:text-5xl">
              Watch the bus. <span className="text-signal">Catch the anomaly.</span>
            </h1>
            <p className="mt-4 max-w-lg text-sm leading-relaxed text-muted-foreground">
              A web console for the CAN-Sentinel Python pipeline. Frames are captured on the isolated
              <span className="font-mono text-foreground"> vcan0 </span>
              interface and scored in 1-second windows by the saved Isolation Forest model on the Linux backend.
            </p>
            <div className="mt-6 flex flex-wrap gap-3">
              <Button asChild variant="signal" size="lg">
                <Link to="/live">
                  <Radio /> Open live monitor
                </Link>
              </Button>
              <Button asChild variant="outline" size="lg">
                <Link to="/analyze">
                  <FileSearch /> Analyze a capture
                </Link>
              </Button>
            </div>
            <div className="mt-6">
              <BusActivityWave source={waveSource} maxBars={48} />
            </div>
          </div>
          <div>
            <div className="eyebrow mb-3">Pipeline readiness</div>
            {status.isError ? <ErrorState error={status.error} /> : <SystemChecks status={status.data} />}
            {status.data && (
              <div className="mt-3 grid grid-cols-2 gap-2 font-mono text-[0.7rem] text-muted-foreground">
                <div className="rounded-lg border px-3 py-2">
                  contamination <span className="float-right text-foreground">{status.data.model.contamination ?? "—"}</span>
                </div>
                <div className="rounded-lg border px-3 py-2">
                  window <span className="float-right text-foreground">{status.data.model.window_ms} ms</span>
                </div>
              </div>
            )}
          </div>
        </div>
      </section>

      <div>
        <div className="mb-3 flex items-center justify-between">
          <div className="eyebrow flex items-center gap-2">
            Latest analysis {latest.data && <span className="normal-case tracking-normal text-foreground">· {latest.data.capture_file}</span>}
            <DemoBadge source={latest.data?.data_source} />
          </div>
          {latestId && (
            <Link to="/analyses/$analysisId" params={{ analysisId: latestId }} className="flex items-center gap-1 text-xs text-primary hover:underline">
              Open <ArrowRight className="size-3" />
            </Link>
          )}
        </div>
        <MetricGrid metrics={metricsOf(latest.data)} />
      </div>

      <div className="grid gap-6 xl:grid-cols-[1.6fr_1fr]">
        <Panel title="Threat score timeline" aside={<span className="font-mono text-xs text-muted-foreground">anomaly score per window</span>}>
          {latest.data ? <ThreatChart windows={latest.data.windows} /> : analyses.isError ? <ErrorState error={analyses.error} /> : <EmptyState title="No analysis yet">Analyze a capture to see scores.</EmptyState>}
        </Panel>
        <div className="space-y-6">
          <Panel title="Recent analyses">
            {analyses.data?.length ? (
              <ul className="space-y-1.5">
                {analyses.data.slice(0, 5).map((a) => (
                  <li key={a.id}>
                    <Link
                      to="/analyses/$analysisId"
                      params={{ analysisId: a.id }}
                      className="flex items-center gap-3 rounded-lg px-2 py-2 hover:bg-secondary/60"
                    >
                      <span className={cn("size-2 rounded-full", a.anomaly_count ? "bg-destructive" : "bg-success")} />
                      <span className="min-w-0 flex-1 truncate font-mono text-xs">{a.capture_file}</span>
                      <span className="font-mono text-xs text-muted-foreground">
                        {a.anomaly_count}/{a.windows_scored}
                      </span>
                      <span className="w-20 text-right text-xs text-muted-foreground">{fmtAgo(a.created_at)}</span>
                    </Link>
                  </li>
                ))}
              </ul>
            ) : (
              <EmptyState title="Nothing analysed yet" />
            )}
          </Panel>
          <Panel title="Recent alerts">
            {alerts.length ? (
              <ul className="space-y-2">
                {alerts.map((e) => (
                  <li key={e.id} className="flex gap-3 rounded-lg border border-destructive/30 bg-destructive/[0.07] px-3 py-2 text-xs">
                    <ShieldAlert className="size-4 shrink-0 text-destructive" />
                    <span className="min-w-0 flex-1">{e.message}</span>
                    {e.demo && <DemoBadge source="demo" />}
                  </li>
                ))}
              </ul>
            ) : (
              <p className="text-sm text-muted-foreground">No alerts this session.</p>
            )}
          </Panel>
        </div>
      </div>
    </div>
  );
}
