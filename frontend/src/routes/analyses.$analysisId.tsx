import { EcuImpactMap } from "@/components/app/EcuImpactMap";
import { BusActivityWave } from "@/components/app/BusActivityWave";
import { createFileRoute, Link } from "@tanstack/react-router";
import { ArrowLeft, Download, Info, Loader2 } from "lucide-react";
import { toast } from "sonner";
import {
  metricsOf,
  useAnalysis,
  useDownloadReport,
  usePlanResponse,
  useActivateResponse,
  useVerifyRecovery,
} from "@/lib/api/queries";
import { useApi } from "@/lib/api";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { DemoBadge } from "@/components/app/DemoNotice";
import { DetectionTable, FrequencyTable } from "@/components/app/DetectionTable";
import { MetricGrid } from "@/components/app/MetricGrid";
import { EmptyState, ErrorState, fmtTime, PageHeader, Panel } from "@/components/app/primitives";
import { ThreatChart } from "@/components/app/ThreatChart";
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
  const { config } = useApi();
  const demoMode = config.mode === "demo";
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
      <EcuImpactMap incidents={a.incidents ?? []} />
      {/* Sentinel X — Incident Center */}
<section className="space-y-4 rounded-xl border bg-card p-5">
  <div className="flex flex-wrap items-center justify-between gap-3">
    <div>
      <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
        Sentinel X
      </p>
      <h2 className="text-xl font-semibold">Incident Center</h2>
      <p className="text-sm text-muted-foreground">
        Correlated anomalous CAN traffic windows
      </p>
    </div>

    <span className="rounded-lg border bg-secondary px-3 py-2 text-sm font-medium">
      {(a.incidents ?? []).length} incidents
    </span>
  </div>

  {(a.incidents ?? []).length === 0 ? (
    <div className="rounded-lg border border-dashed p-6 text-center">
      <p className="font-medium">No correlated incidents</p>
      <p className="mt-1 text-sm text-muted-foreground">
        No consecutive anomalous windows were grouped in this analysis.
      </p>
    </div>
  ) : (
    <div className="space-y-3">
      {(a.incidents ?? []).map((incident) => (
        <article
          key={incident.incident_id}
          className="space-y-3 rounded-lg border p-4"
        >
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div>
              <p className="font-mono text-sm font-semibold">
                {incident.incident_id}
              </p>
              <p className="text-xs text-muted-foreground">
                {incident.status}
              </p>
            </div>

            <span
              className={`rounded-md border px-2.5 py-1 text-xs font-bold ${
                incident.severity === "HIGH"
                  ? "border-destructive/40 bg-destructive/10 text-destructive"
                  : incident.severity === "MEDIUM"
                    ? "border-orange-500/40 bg-orange-500/10 text-orange-600"
                    : "border-muted bg-secondary text-muted-foreground"
              }`}
            >
              {incident.severity}
            </span>
          </div>

          <p className="text-sm">{incident.summary}</p>

          <div className="grid gap-3 text-sm sm:grid-cols-3">
            <div>
              <p className="text-xs text-muted-foreground">Windows</p>
              <p className="font-mono">
                {incident.start_window} – {incident.end_window}
              </p>
            </div>

            <div>
              <p className="text-xs text-muted-foreground">Window count</p>
              <p className="font-mono">{incident.window_count}</p>
            </div>

            <div>
              <p className="text-xs text-muted-foreground">Affected CAN IDs</p>
              <div className="flex flex-wrap gap-1">
                {incident.affected_can_ids.length ? (
                  incident.affected_can_ids.map((id) => (
                    <span
                      key={id}
                      className="rounded border bg-secondary px-2 py-0.5 font-mono text-xs"
                    >
                      {id}
                    </span>
                  ))
                ) : (
                  <span className="text-muted-foreground">Not identified</span>
                )}
              </div>
            </div>
          </div>

          {incident.reasons.length > 0 && (
            <div className="border-t pt-3">
              <p className="mb-2 text-xs font-semibold uppercase tracking-wide text-muted-foreground">
                Evidence
              </p>

              <ul className="space-y-2">
                {incident.reasons.map((reason, index) => (
                  <li key={`${reason.code}-${index}`} className="text-sm">
                    <span className="font-medium">{reason.code}</span>
                    <p className="text-muted-foreground">{reason.message}</p>
                  </li>
                ))}
              </ul>
            </div>
          )}

          <p className="text-xs text-muted-foreground">
            {incident.window_count} correlated windows. Heuristic evidence
            indicates unusual traffic patterns; it does not prove vehicle
            compromise.
          </p>
        <IncidentResponseControls
        analysisId={analysisId}
        incidentId={incident.incident_id}
        demoMode={demoMode}
         />
        </article>
      ))}
    </div>
  )}
</section>

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
function IncidentResponseControls({
  analysisId,
  incidentId,
  demoMode,
}: {
  analysisId: string;
  incidentId: string;
  demoMode: boolean;
}) {
  const plan = usePlanResponse();
  const activate = useActivateResponse();
  const verify = useVerifyRecovery();

  const planned = plan.data;
  const activated = activate.data;
  const recovery = verify.data?.recovery;

  const input = { analysisId, incidentId };

  return (
    <div className="space-y-3 border-t pt-4">
      <div>
        <h3 className="text-sm font-semibold">Response Controls</h3>
        <p className="text-xs text-muted-foreground">
          Offline replay simulation only. No real CAN frames are transmitted.
        </p>
      </div>

      {demoMode && (
        <p className="text-xs text-orange-600">
          Response execution requires backend API mode.
        </p>
      )}

      <div className="flex flex-wrap gap-2">
        <Button
          variant="outline"
          disabled={demoMode || plan.isPending}
          onClick={() =>
            plan.mutate(input, {
              onError: (error) => toast.error("Planning failed", {
                description: error.message,
              }),
            })
          }
        >
          {plan.isPending ? <Loader2 className="animate-spin" /> : null}
          Plan Response
        </Button>

        <Button
          disabled={
            demoMode ||
            !planned ||
            planned.action === "MANUAL_REVIEW" ||
            activate.isPending
          }
          onClick={() =>
            activate.mutate(input, {
              onError: (error) => toast.error("Activation failed", {
                description: error.message,
              }),
            })
          }
        >
          {activate.isPending ? <Loader2 className="animate-spin" /> : null}
          Activate Simulation
        </Button>

        <Button
          variant="outline"
          disabled={
            demoMode ||
            !activated?.replay_result ||
            verify.isPending
          }
          onClick={() =>
            verify.mutate(input, {
              onError: (error) => toast.error("Verification failed", {
                description: error.message,
              }),
            })
          }
        >
          {verify.isPending ? <Loader2 className="animate-spin" /> : null}
          Verify Recovery
        </Button>
      </div>

      {planned && (
        <div className="rounded-lg border bg-secondary/30 p-3 text-sm">
          <p className="font-semibold">Response Plan</p>
          <p>Classification: {planned.classification}</p>
          <p>Action: {planned.action}</p>
          <p>{planned.description}</p>
          <p>Target CAN IDs: {planned.target_can_ids.join(", ") || "None"}</p>
        </div>
      )}

      {activated?.replay_result && (
        <div className="rounded-lg border bg-secondary/30 p-3 text-sm">
          <p className="font-semibold">Offline Replay Results</p>
          <p>Status: {activated.status}</p>
          <p>Frames before: {activated.replay_result.before.total_frames}</p>
          <p>Frames after: {activated.replay_result.after.total_frames}</p>
          <p>Removed frames: {activated.replay_result.removed_frames}</p>
          <p>
            Original capture preserved:{" "}
            {activated.replay_result.original_preserved ? "Yes" : "No"}
          </p>
        </div>
      )}

      {recovery && (
        <div className="rounded-lg border p-3 text-sm">
          <p className="font-semibold">Recovery Verification</p>
          <p>
            Result: {recovery.verified ? "Verified in offline replay" : "Not verified"}
          </p>
          <p>Baseline rate: {recovery.baseline_frame_rate.toFixed(2)} frames/sec</p>
          <p>Replay rate: {recovery.post_mitigation_frame_rate.toFixed(2)} frames/sec</p>
          <p>Remaining unexpected IDs: {recovery.remaining_unexpected_ids}</p>
        </div>
      )}
    </div>
  );
}
