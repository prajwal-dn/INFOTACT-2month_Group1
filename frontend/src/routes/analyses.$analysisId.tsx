import { BusActivityWave } from "@/components/app/BusActivityWave";
import { createFileRoute, Link } from "@tanstack/react-router";
import { ArrowLeft, Download, Info, Loader2 } from "lucide-react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { DemoBadge } from "@/components/app/DemoNotice";
import { DetectionTable, FrequencyTable } from "@/components/app/DetectionTable";
import { MetricGrid } from "@/components/app/MetricGrid";
import { EmptyState, ErrorState, fmtTime, PageHeader, Panel } from "@/components/app/primitives";
import { ThreatChart } from "@/components/app/ThreatChart";
import { metricsOf, useAnalysis, useDownloadReport } from "@/lib/api/queries";
import { pageHead } from "@/lib/head";

export const Route = createFileRoute("/analyses/$analysisId")({
  head: () => pageHead("Analysis result", "Per-window Isolation Forest predictions, anomaly scores and CAN frequency summary."),
  component: AnalysisDetail,
});

function AnalysisDetail() {
  const { analysisId } = Route.useParams();
  const q = useAnalysis(analysisId);
  const report = useDownloadReport();
  const a = q.data;

  if (q.isError)
    return (
      <div className="space-y-4">
        <BackLink />
        <ErrorState error={q.error} />
      </div>
    );
  if (!a) return <div className="h-96 animate-pulse rounded-2xl bg-secondary/40" />;

  return (
    <div className="space-y-6">
      <BackLink />
      <PageHeader
        eyebrow={`Analysis · ${a.origin}`}
        title={<span className="flex flex-wrap items-center gap-3 break-all font-mono text-2xl md:text-3xl">{a.capture_file} <DemoBadge source={a.data_source} /></span>}
        description={`${a.frames_loaded.toLocaleString()} frames loaded · analysed ${fmtTime(a.created_at)} UTC`}
        actions={
          <Button
            variant="outline"
            onClick={() =>
              report.mutate(a.id, {
                onSuccess: (f) => toast.success("Report downloaded", { description: f }),
                onError: (e) => toast.error("Download failed", { description: e.message }),
              })
            }
            disabled={report.isPending}
          >
            {report.isPending ? <Loader2 className="animate-spin" /> : <Download />} Inference report CSV
          </Button>
        }
      />

      {a.notes.length > 0 && (
        <div className={a.data_source === "demo" ? "demo-stripes rounded-xl border border-demo/40 p-4" : "rounded-xl border bg-secondary/40 p-4"}>
          {a.notes.map((n) => (
            <p key={n} className="flex gap-2 text-sm">
              <Info className="mt-0.5 size-4 shrink-0 text-demo" /> {n}
            </p>
          ))}
        </div>
      )}

      <MetricGrid metrics={metricsOf(a)} />

      <BusActivityWave
        source={{ kind: "analysis", windows: a.windows, excludedPartialWindow: a.excluded_partial_window, dataSource: a.data_source, label: "Saved analysis" }}
        maxBars={120}
        height={120}
      />

      <Tabs defaultValue="matrix">
        <TabsList className="mb-4">
          <TabsTrigger value="matrix">Detection matrix</TabsTrigger>
          <TabsTrigger value="chart">Threat score</TabsTrigger>
          <TabsTrigger value="frequency">Frequency summary</TabsTrigger>
          <TabsTrigger value="model">Model</TabsTrigger>
        </TabsList>
        <TabsContent value="matrix">
          <Panel aside={<span className="text-xs text-muted-foreground">click a row to inspect its feature vector</span>} title="1-second window scoring">
            {a.windows.length ? <DetectionTable windows={a.windows} /> : <EmptyState title="No windows" />}
          </Panel>
        </TabsContent>
        <TabsContent value="chart">
          <Panel title="Anomaly score per window">
            <ThreatChart windows={a.windows} height={400} />
          </Panel>
        </TabsContent>
        <TabsContent value="frequency">
          <Panel title="Per-ID frequency and inter-arrival timing">
            {a.frequency_summary.length ? <FrequencyTable rows={a.frequency_summary} /> : <EmptyState title="Not provided by backend" />}
          </Panel>
        </TabsContent>
        <TabsContent value="model">
          <Panel title="Saved model used for this run">
            <dl className="grid gap-x-8 gap-y-3 font-mono text-xs sm:grid-cols-2">
              {[
                ["algorithm", a.model.algorithm],
                ["path", a.model.path],
                ["contamination", a.model.contamination ?? "—"],
                ["training windows", a.model.training_windows ?? "—"],
                ["window size", `${a.model.window_ms} ms`],
                ["scikit-learn", a.model.sklearn_version ?? "—"],
                ["excluded partial window", a.excluded_partial_window ?? "none"],
              ].map(([k, v]) => (
                <div key={String(k)} className="flex justify-between gap-4 border-b pb-2">
                  <dt className="text-muted-foreground">{k}</dt>
                  <dd className="text-right">{String(v)}</dd>
                </div>
              ))}
            </dl>
            <div className="eyebrow mb-2 mt-6">Feature columns</div>
            <div className="flex flex-wrap gap-1.5">
              {a.model.feature_columns.map((c) => (
                <span key={c} className="rounded-md border bg-secondary/40 px-2 py-0.5 font-mono text-[0.68rem]">
                  {c}
                </span>
              ))}
            </div>
          </Panel>
        </TabsContent>
      </Tabs>
      <p className="text-xs text-muted-foreground">Prototype predictions on virtual-CAN data; not validated real-world detection accuracy.</p>
    </div>
  );
}

function BackLink() {
  return (
    <Link to="/analyses" className="inline-flex items-center gap-1.5 text-xs text-muted-foreground hover:text-foreground">
      <ArrowLeft className="size-3.5" /> All analyses
    </Link>
  );
}
