import { useRef, useState } from "react";
import { createFileRoute, useNavigate } from "@tanstack/react-router";
import { FileUp, FolderOpen, Loader2, Play } from "lucide-react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { DemoBadge } from "@/components/app/DemoNotice";
import { ErrorState, PageHeader, Panel } from "@/components/app/primitives";
import { logEvent } from "@/lib/audit-log";
import { analyzeDoneMessage, analyzeErrorMessage, analyzeStartMessage, uploadStartMessage } from "@/lib/audit-messages";
import { useBackendConfig, type AnalysisResult } from "@/lib/api";
import { CAPTURE_HEADER } from "@/lib/api/capture-file";
import { useAnalyzeCapture, usePresets, useUploadCapture } from "@/lib/api/queries";
import { pageHead } from "@/lib/head";
import { cn } from "@/lib/utils";

export const Route = createFileRoute("/analyze")({
  head: () => pageHead("Analyze capture", "Run saved-model Isolation Forest inference on a recorded virtual-CAN capture."),
  component: Analyze,
});

function Analyze() {
  const { mode } = useBackendConfig();
  const navigate = useNavigate();
  const presets = usePresets();
  const analyze = useAnalyzeCapture();
  const upload = useUploadCapture();
  const [selected, setSelected] = useState<string | null>(null);
  const [path, setPath] = useState("");
  const [dragOver, setDragOver] = useState(false);
  const fileRef = useRef<HTMLInputElement>(null);
  const busy = analyze.isPending || upload.isPending;

  // One token per user action, so a handler that fires twice for the same click
  // cannot append the entry twice while a genuine second run still gets its own.
  const actionSeq = useRef(0);

  const done = (a: AnalysisResult) => {
    const demo = a.data_source === "demo";
    logEvent(a.anomaly_count ? "ALERT" : "SUCCESS", analyzeDoneMessage(demo, a), demo, `analysis:${a.id}`);
    navigate({ to: "/analyses/$analysisId", params: { analysisId: a.id } });
  };
  const fail = (e: Error) => {
    logEvent("ALERT", analyzeErrorMessage(mode === "demo", e.message), mode === "demo");
    toast.error("Analysis failed", { description: e.message });
  };

  const runPath = (capture_path: string, origin: "preset" | "path") => {
    logEvent(
      "INFO",
      analyzeStartMessage(mode === "demo", capture_path),
      mode === "demo",
      `analyze-start:${capture_path}:${++actionSeq.current}`,
    );
    analyze.mutate({ capture_path, origin }, { onSuccess: done, onError: fail });
  };
  const runFile = (file: File) => {
    logEvent(
      "INFO",
      uploadStartMessage(mode === "demo", file.name),
      mode === "demo",
      `upload-start:${file.name}:${++actionSeq.current}`,
    );
    upload.mutate(file, { onSuccess: done, onError: fail });
  };

  return (
    <div>
      <PageHeader
        eyebrow="Saved-capture inference"
        title={<span className="flex items-center gap-3">Analyze a capture <DemoBadge /></span>}
        description="The backend validates the sniffer CSV, builds 1-second window features, excludes the possibly partial final window and scores each window with the saved Isolation Forest — without retraining."
      />

      <div className="grid gap-6 lg:grid-cols-2">
        <Panel title="Preset captures">
          {presets.isError && <ErrorState error={presets.error} />}
          <div className="space-y-2">
            {(presets.data ?? []).map((p) => (
              <button
                key={p.id}
                type="button"
                disabled={!p.available || busy}
                onClick={() => setSelected(p.path)}
                className={cn(
                  "flex w-full items-center gap-4 rounded-xl border px-4 py-3 text-left transition-all hover:border-primary/40 disabled:opacity-50",
                  selected === p.path && "border-primary/60 bg-accent/40 glow-primary",
                )}
              >
                <span className={cn("size-3 rounded-full border-2", selected === p.path ? "border-primary bg-primary" : "border-muted-foreground")} />
                <span className="flex-1">
                  <span className="block text-sm font-medium">{p.label}</span>
                  <span className="block font-mono text-[0.7rem] text-muted-foreground">{p.path}</span>
                </span>
                {!p.available && <span className="text-xs text-destructive">missing</span>}
              </button>
            ))}
            {presets.isLoading && <div className="h-40 animate-pulse rounded-xl bg-secondary/50" />}
          </div>
          <Button className="mt-4 w-full" variant="signal" size="lg" disabled={!selected || busy} onClick={() => selected && runPath(selected, "preset")}>
            {analyze.isPending ? <Loader2 className="animate-spin" /> : <Play />} Run analysis
          </Button>
        </Panel>

        <div className="space-y-6">
          <Panel title="Capture on the backend host">
            <p className="mb-3 text-xs text-muted-foreground">Path relative to the CAN-Sentinel repository root, e.g. a file recorded into <span className="font-mono">data/</span>.</p>
            <form
              className="flex gap-2"
              onSubmit={(e) => {
                e.preventDefault();
                if (path.trim()) runPath(path.trim(), "path");
              }}
            >
              <div className="relative flex-1">
                <FolderOpen className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" />
                <Input value={path} onChange={(e) => setPath(e.target.value)} placeholder="data/normal_baseline_60s.csv" className="pl-9 font-mono text-xs" aria-label="Capture file path" />
              </div>
              <Button type="submit" variant="secondary" disabled={!path.trim() || busy}>
                Analyze
              </Button>
            </form>
          </Panel>

          <Panel title="Upload a capture">
            <input
              ref={fileRef}
              type="file"
              accept=".csv,text/csv"
              className="hidden"
              aria-label="Capture CSV file"
              onChange={(e) => {
                const f = e.target.files?.[0];
                if (f) runFile(f);
                e.target.value = "";
              }}
            />
            <button
              type="button"
              disabled={busy}
              onClick={() => fileRef.current?.click()}
              onDragOver={(e) => {
                e.preventDefault();
                setDragOver(true);
              }}
              onDragLeave={() => setDragOver(false)}
              onDrop={(e) => {
                e.preventDefault();
                setDragOver(false);
                const f = e.dataTransfer.files?.[0];
                if (f) runFile(f);
              }}
              className={cn(
                "grid w-full place-items-center rounded-xl border border-dashed px-6 py-10 text-center transition-colors hover:border-primary/50 hover:bg-accent/20",
                dragOver && "border-primary bg-accent/30",
              )}
            >
              {upload.isPending ? <Loader2 className="size-6 animate-spin text-primary" /> : <FileUp className="size-6 text-primary" />}
              <span className="mt-3 text-sm font-medium">Drop a sniffer CSV or click to browse</span>
              <span className="mt-1 font-mono text-[0.65rem] text-muted-foreground">{CAPTURE_HEADER}</span>
            </button>
            {mode === "demo" && (
              <p className="mt-3 text-xs text-demo">In demo mode only the header is checked; the file is not analysed.</p>
            )}
          </Panel>
        </div>
      </div>
    </div>
  );
}
