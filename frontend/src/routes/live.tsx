import { useEffect, useRef, useState } from "react";
import { createFileRoute, useNavigate } from "@tanstack/react-router";
import { AlertCircle, AlertTriangle, Loader2, Radio, ShieldAlert, Square, Zap } from "lucide-react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { DemoBadge } from "@/components/app/DemoNotice";
import { DetectionTable } from "@/components/app/DetectionTable";
import { MetricGrid } from "@/components/app/MetricGrid";
import { EmptyState, ErrorState, PageHeader, Panel } from "@/components/app/primitives";
import { checksFor, SystemChecks } from "@/components/app/SystemChecks";
import { ThreatChart } from "@/components/app/ThreatChart";
import { SecurityAlertModal } from "@/components/app/SecurityAlertModal";
import { SecurityEventTimeline } from "@/components/app/SecurityEventTimeline";
import { useSecurityTimeline } from "@/lib/use-security-timeline";
import { logEvent } from "@/lib/audit-log";
import { liveAnomalyMessage, liveStartMessage, liveStopMessage } from "@/lib/audit-messages";
import { useBackendConfig } from "@/lib/api";
import { BusActivityWave } from "@/components/app/BusActivityWave";
import { setActiveLiveSession } from "@/lib/live-session-store";
import { useLiveSession, useStartLive, useStartLiveAttack, useStatus, useStopLive } from "@/lib/api/queries";
import type { LiveIncident } from "@/lib/api/schemas";
import { pageHead } from "@/lib/head";
import { cn } from "@/lib/utils";

export const Route = createFileRoute("/live")({
  head: () => pageHead("Live monitor", "Start a capture on the virtual vcan0 interface and watch completed windows scored in real time."),
  component: LiveMonitor,
});

function elapsed(startIso: string) {
  const s = Math.max(0, Math.floor((Date.now() - Date.parse(startIso)) / 1000));
  return `${String(Math.floor(s / 60)).padStart(2, "0")}:${String(s % 60).padStart(2, "0")}`;
}

function LiveMonitor() {
  const { mode } = useBackendConfig();
  const demo = mode === "demo";
  const navigate = useNavigate();
  const status = useStatus();
  const [sessionId, setSessionId] = useState<string | null>(null);
  const start = useStartLive();
  const stop = useStopLive();
  const attack = useStartLiveAttack();
  const [attackMode, setAttackMode] = useState<1 | 2>(1);
  const session = useLiveSession(sessionId, !stop.isPending);
  const s = session.data;
  const capturing = s?.state === "capturing";
  const seen = useRef(new Set<number>());

  // Incident alert state: tracks acknowledged incidents to prevent duplicate popups
  const [acknowledgedIncidents, setAcknowledgedIncidents] = useState<Set<string>>(() => new Set());
  const [activeIncident, setActiveIncident] = useState<LiveIncident | null>(null);
  const [isAlertModalOpen, setIsAlertModalOpen] = useState(false);

  useEffect(() => setActiveLiveSession(capturing && sessionId ? sessionId : null), [capturing, sessionId]);
  const ready = checksFor(status.data).every((c) => c.ok || c.demo);

  // Monitor windows for anomaly toasts
  useEffect(() => {
    if (!s) return;
    for (const w of s.windows) {
      if (seen.current.has(w.window_index)) continue;
      seen.current.add(w.window_index);
      if (w.prediction === "ANOMALY") {
        const demo = s.data_source === "demo";
        logEvent("ALERT", liveAnomalyMessage(demo, w), demo, `live-anomaly:${s.id}:${w.window_index}`);
        toast.error(`Intrusion alert · window #${w.window_index}`, {
          id: "live-alert",
          description: `${s.data_source === "demo" ? "DEMO · " : ""}Score ${w.anomaly_score.toFixed(4)} · ${w.features.unique_can_ids} IDs · ${w.features.total_frames} frames`,
        });
      }
    }
  }, [s]);

  // Trigger modal when backend confirms a new security incident
  useEffect(() => {
    if (!s || !s.incidents || s.incidents.length === 0) return;
    const incidents = s.incidents;

    // Keep active incident updated with latest live status (e.g. recovery progress)
    if (activeIncident) {
      const updated = incidents.find((inc) => inc.incident_id === activeIncident.incident_id);
      if (updated && updated !== activeIncident) {
        setActiveIncident(updated);
      }
    }

    // Trigger popup for newly confirmed unacknowledged incidents
    const unacknowledged = incidents.filter((inc) => !acknowledgedIncidents.has(inc.incident_id));
    if (unacknowledged.length > 0 && !isAlertModalOpen) {
      const latest = unacknowledged[unacknowledged.length - 1];
      setActiveIncident(latest);
      setIsAlertModalOpen(true);
    }
  }, [s?.incidents, acknowledgedIncidents, activeIncident, isAlertModalOpen]);

  const handleCloseAlertModal = () => {
    if (activeIncident) {
      setAcknowledgedIncidents((prev) => new Set(prev).add(activeIncident.incident_id));
    }
    setIsAlertModalOpen(false);
  };

  const handleOpenAnalysis = (analysisId: string) => {
    if (activeIncident) {
      setAcknowledgedIncidents((prev) => new Set(prev).add(activeIncident.incident_id));
    }
    setIsAlertModalOpen(false);
    navigate({ to: "/analyses/$analysisId", params: { analysisId } });
  };

  const onStart = () =>
    start.mutate(undefined, {
      onSuccess: (live) => {
        seen.current.clear();
        setAcknowledgedIncidents(new Set());
        setActiveIncident(null);
        setIsAlertModalOpen(false);
        setSessionId(live.id);
        const demo = live.data_source === "demo";
        logEvent("INFO", liveStartMessage(demo, live.interface, live.capture_file), demo, `live-start:${live.id}`);
      },
      onError: (e) => toast.error("Capture failed to start", { description: e.message }),
    });

  const onStartAttack = () => {
    if (!sessionId) return;
    attack.mutate({ id: sessionId, mode: attackMode }, {
      onSuccess: (result) => toast.success(`Attack simulator started · PID ${result.pid}`),
      onError: (e) => toast.error("Attack simulator failed to start", { description: e.message }),
    });
  };

  const onStop = () => {
    if (!sessionId) return;
    stop.mutate(sessionId, {
      onSuccess: (a) => {
        const demo = a.data_source === "demo";
        logEvent(a.anomaly_count ? "ALERT" : "SUCCESS", liveStopMessage(demo, a), demo, `analysis:${a.id}`);
        setSessionId(null);
        navigate({ to: "/analyses/$analysisId", params: { analysisId: a.id } });
      },
      onError: (e) => toast.error("Stop & analyze failed", { description: e.message }),
    });
  };

  const timelineEvents = useSecurityTimeline(s);

  const windows = s?.windows ?? [];
  const anomalies = windows.filter((w) => w.prediction === "ANOMALY").length;
  const recentAlert = windows.slice(-3).some((w) => w.prediction === "ANOMALY");
  const confirmedIncidents = s?.incidents ?? [];

  return (
    <div>
      <PageHeader
        eyebrow="Live monitor"
        title={<span className="flex items-center gap-3">Capture on vcan0 <DemoBadge /></span>}
        description="The backend starts the C sniffer on the isolated virtual interface. Each completed 1-second window is scored with the saved model; the newest window stays pending until it closes."
        actions={
          capturing || stop.isPending ? (
            <Button variant="destructive" size="lg" onClick={onStop} disabled={stop.isPending}>
              {stop.isPending ? <Loader2 className="animate-spin" /> : <Square />} Stop &amp; analyze
            </Button>
          ) : (
            <Button variant="live" size="lg" onClick={onStart} disabled={start.isPending || !ready}>
              {start.isPending ? <Loader2 className="animate-spin" /> : <Radio />} Start capture
            </Button>
          )
        }
      />

      <div className="grid gap-6 xl:grid-cols-[320px_minmax(0,1fr)]">
        <div className="space-y-6">
          <Panel title="Pre-flight checks">
            {status.isError ? <ErrorState error={status.error} /> : <SystemChecks status={status.data} />}
            {!ready && status.data && (
              <p className="mt-3 text-xs text-muted-foreground">
                Bring vcan0 up on the backend host:
                <code className="mt-1 block rounded-md bg-secondary p-2 font-mono text-[0.68rem] text-foreground">
                  sudo modprobe vcan{"\n"}sudo ip link add dev vcan0 type vcan{"\n"}sudo ip link set up vcan0
                </code>
              </p>
            )}
          </Panel>
          <Panel title="Session">
            {s ? (
              <dl className="space-y-2 font-mono text-xs">
                <Row k="state" v={<span className={cn(capturing ? "text-warning" : "text-muted-foreground")}>{s.state}</span>} />
                <Row k="elapsed" v={elapsed(s.started_at)} />
                <Row k="frames" v={s.frames_captured.toLocaleString()} />
                <Row k="pending window" v={s.pending_window_index ?? "—"} />
                <Row k="file" v={<span className="break-all">{s.capture_file}</span>} />
              </dl>
            ) : (
              <p className="text-sm text-muted-foreground">No capture running.</p>
            )}
            {demo && (
              <p className="mt-3 rounded-lg border border-demo/30 bg-demo/10 p-2.5 text-[0.7rem] leading-relaxed text-demo">
                Demo follows a scripted timeline with two illustrative anomaly bursts. Nothing is captured.
              </p>
            )}
          </Panel>
          { !demo && capturing && s?.interface === "vcan0" && (
            <Panel title="Isolated attack simulator" aside={<span className="text-xs text-muted-foreground">vcan0 only</span>}>
              <p className="text-xs leading-relaxed text-muted-foreground">
                Generates lab traffic on the virtual CAN interface. Detection automatically stops this simulator; capture continues.
              </p>
              <div className="mt-3 flex flex-wrap gap-2">
                <Button size="sm" variant={attackMode === 1 ? "default" : "outline"} onClick={() => setAttackMode(1)} disabled={attack.isPending || s?.attack?.state === "RUNNING"}>
                  Mode 1 · Flood
                </Button>
                <Button size="sm" variant={attackMode === 2 ? "default" : "outline"} onClick={() => setAttackMode(2)} disabled={attack.isPending || s?.attack?.state === "RUNNING"}>
                  Mode 2 · Extended ID
                </Button>
                <Button size="sm" onClick={onStartAttack} disabled={attack.isPending || s?.attack?.state === "RUNNING" || s?.recovery?.state === "ATTACK_STOPPED_VERIFYING"}>
                  {attack.isPending ? <Loader2 className="animate-spin" /> : <Zap />} Start attack
                </Button>
              </div>
              <dl className="mt-3 space-y-2 font-mono text-xs">
                <Row k="simulator" v={s?.attack?.state ?? "NOT_STARTED"} />
                <Row k="recovery" v={s?.recovery?.state ?? "NOT_STARTED"} />
                <Row k="normal windows" v={`${s?.recovery?.normal_windows ?? 0} / ${s?.recovery?.required_normal_windows ?? 2}`} />
              </dl>
              {s?.recovery?.state === "RECOVERED" && <p className="mt-3 text-xs text-success">Two consecutive normal model windows observed after the simulator stopped. This is model-based recovery evidence, not proof of vehicle or ECU health.</p>}
              {s?.recovery?.state === "ATTACK_STOPPED_VERIFYING" && <p className="mt-3 text-xs text-warning">Simulator stopped automatically. Waiting for two consecutive normal windows; capture remains active.</p>}
            </Panel>
          )}
        </div>

        <div className="min-w-0 space-y-6">
          {confirmedIncidents.length > 0 && (
            <div className="surface flex flex-wrap items-center justify-between gap-3 border-l-4 border-l-destructive bg-destructive/10 p-4">
              <div className="flex items-center gap-3">
                <ShieldAlert className="size-5 shrink-0 text-destructive" />
                <div>
                  <div className="font-semibold text-sm text-foreground">
                    Confirmed Security Incident: {confirmedIncidents[confirmedIncidents.length - 1].incident_id}
                  </div>
                  <div className="text-xs text-muted-foreground">
                    {confirmedIncidents.length} incident{confirmedIncidents.length > 1 ? "s" : ""} confirmed by backend Isolation Forest
                  </div>
                </div>
              </div>
              <Button
                size="sm"
                variant="destructive"
                onClick={() => {
                  setActiveIncident(confirmedIncidents[confirmedIncidents.length - 1]);
                  setIsAlertModalOpen(true);
                }}
              >
                View SOC Alert
              </Button>
            </div>
          )}

          {capturing && (
            <div
              className={cn(
                "surface relative flex items-center gap-4 overflow-hidden px-5 py-4 transition-all",
                recentAlert && "surface-alert",
              )}
            >
              <span className={cn("size-2.5 rounded-full animate-pulse-dot", recentAlert ? "bg-destructive" : "bg-success")} />
              <div className="flex-1">
                <div className="font-display text-lg font-semibold">
                  {recentAlert ? "Anomalous traffic detected" : "Bus traffic within baseline"}
                </div>
                <div className="text-xs text-muted-foreground">
                  {windows.length} windows scored · {anomalies} anomalous · window #{s?.pending_window_index ?? 0} pending
                </div>
              </div>
              {recentAlert && <ShieldAlert className="size-6 text-destructive" />}
              <div className="pointer-events-none absolute inset-x-0 bottom-0 h-px overflow-hidden">
                <div className={cn("h-px w-1/3 animate-sweep", recentAlert ? "bg-destructive" : "bg-primary")} />
              </div>
            </div>
          )}

          <MetricGrid
            metrics={s ? { total: windows.length, normal: windows.length - anomalies, anomalies, rate: windows.length ? (anomalies / windows.length) * 100 : 0 } : null}
          />

          {session.isError && <ErrorState error={session.error} />}

          {s && (
            <BusActivityWave
              source={{ kind: "live", windows, pendingWindowIndex: s.pending_window_index, dataSource: s.data_source, capturing }}
              height={120}
            />
          )}

          <Panel title="Threat score" aside={<DemoBadge source={s?.data_source} />}>
            {windows.length ? (
              <ThreatChart windows={windows} height={260} />
            ) : (
              <EmptyState title={capturing ? "Waiting for a completed window…" : "Start a capture to stream results"} />
            )}
          </Panel>

          <Panel title="Detection matrix" aside={<span className="text-xs text-muted-foreground">newest first · click a row for features</span>}>
            {windows.length ? <DetectionTable windows={windows} newestFirst maxHeight={420} /> : <EmptyState title="No windows scored yet" />}
          </Panel>

          <SecurityEventTimeline events={timelineEvents} capturing={capturing} />
        </div>
      </div>

      <SecurityAlertModal
        incident={activeIncident}
        session={s ?? null}
        isOpen={isAlertModalOpen}
        onClose={handleCloseAlertModal}
        onOpenAnalysis={handleOpenAnalysis}
      />
    </div>
  );
}

function Row({ k, v }: { k: string; v: React.ReactNode }) {
  return (
    <div className="flex justify-between gap-4">
      <dt className="text-muted-foreground">{k}</dt>
      <dd className="text-right">{v}</dd>
    </div>
  );
}
