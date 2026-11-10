import { useEffect, useRef, useState } from "react";
import { createFileRoute, useNavigate } from "@tanstack/react-router";
import {
  Activity,
  AlertCircle,
  AlertOctagon,
  AlertTriangle,
  Loader2,
  Play,
  Radio,
  ShieldAlert,
  Square,
  Zap,
} from "lucide-react";
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
import { AttackPreventionAnalytics } from "@/components/app/AttackPreventionAnalytics";
import { IncidentReportModal } from "@/components/app/IncidentReportModal";
import { IncidentHistoryTable } from "@/components/app/IncidentHistoryTable";
import { SocOverviewDashboard } from "@/components/app/SocOverviewDashboard";
import { RealTimeTrafficMonitor } from "@/components/app/RealTimeTrafficMonitor";
import { ThreatMonitoringPanel } from "@/components/app/ThreatMonitoringPanel";
import { SystemHealthMonitor } from "@/components/app/SystemHealthMonitor";
import { ResponseReliabilityDashboard } from "@/components/app/ResponseReliabilityDashboard";
import { useSecurityTimeline } from "@/lib/use-security-timeline";
import { useAttackAnalytics } from "@/lib/use-attack-analytics";
import { logEvent } from "@/lib/audit-log";
import { liveAnomalyMessage, liveStartMessage, liveStopMessage } from "@/lib/audit-messages";
import { useBackendConfig } from "@/lib/api";
import { BusActivityWave } from "@/components/app/BusActivityWave";
import { getActiveLiveSessionId, setActiveLiveSession } from "@/lib/live-session-store";
import {
  useActiveLiveSessionQuery,
  useAllIncidents,
  useLiveSession,
  useStartLive,
  useStartLiveAttack,
  useStopLiveAttack,
  useStartLiveNormal,
  useStopLiveNormal,
  useStopLiveSimulations,
  useStatus,
  useStopLive,
} from "@/lib/api/queries";
import type { LiveIncident } from "@/lib/api/schemas";
import { pageHead } from "@/lib/head";
import { cn } from "@/lib/utils";

export const Route = createFileRoute("/live")({
  head: () =>
    pageHead(
      "Live monitor",
      "Start a capture on the virtual vcan0 interface and watch completed windows scored in real time.",
    ),
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
  const [sessionId, setSessionId] = useState<string | null>(() => getActiveLiveSessionId());
  const start = useStartLive();
  const stop = useStopLive();
  // Always query the backend for an active session on mount — this recovers
  // from stale localStorage IDs and from navigation-away-and-back.
  // Disabled only while a stop mutation is in-flight to avoid re-latching.
  const activeQuery = useActiveLiveSessionQuery(!stop.isPending);
  const attack = useStartLiveAttack();
  const stopAttack = useStopLiveAttack();
  const startNormal = useStartLiveNormal();
  const stopNormal = useStopLiveNormal();
  const stopSimulations = useStopLiveSimulations();
  const [attackMode, setAttackMode] = useState<1 | 2>(1);
  const session = useLiveSession(sessionId, !stop.isPending);
  const s =
    session.data && session.data.state === "capturing"
      ? session.data
      : activeQuery.data && activeQuery.data.state === "capturing"
        ? activeQuery.data
        : session.data;
  const capturing = s?.state === "capturing";
  const seen = useRef(new Set<number>());

  // Incident alert state: tracks acknowledged incidents to prevent duplicate popups
  const [acknowledgedIncidents, setAcknowledgedIncidents] = useState<Set<string>>(() => new Set());
  const [activeIncident, setActiveIncident] = useState<LiveIncident | null>(null);
  const [isAlertModalOpen, setIsAlertModalOpen] = useState(false);

  // Phase 5: Detailed Incident Investigation Report modal state
  const [selectedReportIncident, setSelectedReportIncident] = useState<LiveIncident | null>(null);
  const [isReportModalOpen, setIsReportModalOpen] = useState(false);
  const allIncidents = useAllIncidents();

  // Restore active session discovered from backend if store was empty OR had a stale ID
  useEffect(() => {
    const backendId = activeQuery.data?.id;
    const backendState = activeQuery.data?.state;
    if (backendId && backendState === "capturing" && backendId !== sessionId) {
      setSessionId(backendId);
      setActiveLiveSession(backendId);
    }
  }, [sessionId, activeQuery.data]);

  // Synchronize active session with store and cleanup when stopped or invalid.
  // Guard: don't wipe session while activeQuery is in-flight or if backend has an active session.
  useEffect(() => {
    const backendIsActive = activeQuery.data?.state === "capturing";
    const backendConfirmedNoSession = activeQuery.isFetched && !activeQuery.data;
    if ((s && s.state === "stopped") || (session.isError && backendConfirmedNoSession)) {
      setActiveLiveSession(null);
      setSessionId(null);
    } else if (capturing && s?.id) {
      setActiveLiveSession(s.id);
    }
  }, [session.isError, s, capturing, activeQuery.data, activeQuery.isFetched]);

  const ready = checksFor(status.data).every((c) => c.ok || c.demo);

  // Monitor windows for anomaly toasts
  useEffect(() => {
    if (!s) return;
    for (const w of s.windows) {
      if (seen.current.has(w.window_index)) continue;
      seen.current.add(w.window_index);
      if (w.prediction === "ANOMALY") {
        const demo = s.data_source === "demo";
        logEvent(
          "ALERT",
          liveAnomalyMessage(demo, w),
          demo,
          `live-anomaly:${s.id}:${w.window_index}`,
        );
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
      if (latest) {
        setActiveIncident(latest);
        setIsAlertModalOpen(true);
      }
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

  const onStart = () => {
    if (capturing) return;
    start.mutate(undefined, {
      onSuccess: (live) => {
        seen.current.clear();
        setAcknowledgedIncidents(new Set());
        setActiveIncident(null);
        setIsAlertModalOpen(false);
        setSessionId(live.id);
        setActiveLiveSession(live.id);
        const demo = live.data_source === "demo";
        logEvent(
          "INFO",
          liveStartMessage(demo, live.interface, live.capture_file),
          demo,
          `live-start:${live.id}`,
        );
      },
      onError: (e) => toast.error("Capture failed to start", { description: e.message }),
    });
  };

  const isNormalRunning = s?.normal?.state === "RUNNING";
  const isAttackRunning = s?.attack?.state === "RUNNING";

  const onStartNormal = () => {
    if (!sessionId) return;
    startNormal.mutate(
      { id: sessionId },
      {
        onSuccess: (result) =>
          toast.success(`Normal traffic generator started · PID ${result.pid ?? "—"}`, {
            description:
              "Transmitting legitimate RPM (0x100), Speed (0x101), and Coolant (0x102) frames.",
          }),
        onError: (e) =>
          toast.error("Normal traffic generator failed to start", { description: e.message }),
      },
    );
  };

  const onStopNormal = () => {
    if (!sessionId) return;
    stopNormal.mutate(sessionId, {
      onSuccess: () => toast.success("Normal traffic generator stopped"),
      onError: (e) => toast.error("Failed to stop normal traffic", { description: e.message }),
    });
  };

  const onStartAttack = () => {
    if (!sessionId) return;
    attack.mutate(
      { id: sessionId, mode: attackMode },
      {
        onSuccess: (result) =>
          toast.success(`Attack simulator started · Mode ${result.mode} · PID ${result.pid}`, {
            description:
              result.mode === 1
                ? "Flooding 0x100 @ 1ms"
                : "Injecting unexpected extended ID 0x999 @ 50ms",
          }),
        onError: (e) => toast.error("Attack simulator failed to start", { description: e.message }),
      },
    );
  };

  const onStopAllSimulations = () => {
    if (!sessionId) return;
    stopSimulations.mutate(sessionId, {
      onSuccess: () => toast.success("All simulations stopped · Live CAN capture continues"),
      onError: (e) => toast.error("Failed to stop simulations", { description: e.message }),
    });
  };

  const onStop = () => {
    if (!sessionId) return;
    stop.mutate(sessionId, {
      onSuccess: (a) => {
        const demo = a.data_source === "demo";
        logEvent(
          a.anomaly_count ? "ALERT" : "SUCCESS",
          liveStopMessage(demo, a),
          demo,
          `analysis:${a.id}`,
        );
        setActiveLiveSession(null);
        setSessionId(null);
        navigate({ to: "/analyses/$analysisId", params: { analysisId: a.id } });
      },
      onError: (e) => toast.error("Stop & analyze failed", { description: e.message }),
    });
  };

  const timelineEvents = useSecurityTimeline(s);
  const attackAnalytics = useAttackAnalytics(s);

  const windows = s?.windows ?? [];
  const anomalies = windows.filter((w) => w.prediction === "ANOMALY").length;
  const recentAlert = windows.slice(-3).some((w) => w.prediction === "ANOMALY");
  const confirmedIncidents = s?.incidents ?? [];

  return (
    <div>
      <PageHeader
        eyebrow="Live monitor"
        title={
          <span className="flex items-center gap-3">
            Capture on vcan0 <DemoBadge />
          </span>
        }
        description="The backend starts the C sniffer on the isolated virtual interface. Each completed 1-second window is scored with the saved model; the newest window stays pending until it closes."
        actions={
          capturing || stop.isPending ? (
            <Button variant="destructive" size="lg" onClick={onStop} disabled={stop.isPending}>
              {stop.isPending ? <Loader2 className="animate-spin" /> : <Square />} Stop &amp;
              analyze
            </Button>
          ) : (
            <Button
              variant="live"
              size="lg"
              onClick={onStart}
              disabled={start.isPending || !ready || (sessionId !== null && !session.isError)}
            >
              {start.isPending || (sessionId !== null && session.isLoading) ? (
                <Loader2 className="animate-spin" />
              ) : (
                <Radio />
              )}{" "}
              Start capture
            </Button>
          )
        }
      />

      {/* Phase 6: SOC Overview Dashboard */}
      <div className="mb-6">
        <SocOverviewDashboard
          session={s ?? null}
          status={status.data}
          totalHistoricalIncidents={allIncidents.data?.length ?? 0}
        />
      </div>

      {/* Phase 6: System Health Monitoring — full-width above the two-column grid */}
      <div className="mb-6">
        <SystemHealthMonitor
          status={status.data}
          session={s ?? null}
          isStatusError={status.isError}
        />
      </div>

      {/* Session, Pre-flight checks & Simulation Controls */}
      <div
        className={cn(
          "grid gap-6",
          !demo && capturing && s?.interface === "vcan0"
            ? "grid-cols-1 md:grid-cols-2 xl:grid-cols-3"
            : "grid-cols-1 md:grid-cols-2",
        )}
      >
        <Panel title="Pre-flight checks">
          {status.isError ? (
            <ErrorState error={status.error} />
          ) : (
            <SystemChecks status={status.data} />
          )}
          {!ready && status.data && (
            <p className="mt-3 text-xs text-muted-foreground">
              Bring vcan0 up on the backend host:
              <code className="mt-1 block rounded-md bg-secondary p-2 font-mono text-[0.68rem] text-foreground">
                sudo modprobe vcan{"\n"}sudo ip link add dev vcan0 type vcan{"\n"}sudo ip link set
                up vcan0
              </code>
            </p>
          )}
        </Panel>
        <Panel title="Session">
          {s ? (
            <dl className="space-y-2 font-mono text-xs">
              <Row
                k="state"
                v={
                  <span className={cn(capturing ? "text-warning" : "text-muted-foreground")}>
                    {s.state}
                  </span>
                }
              />
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
              Demo follows a scripted timeline with two illustrative anomaly bursts. Nothing is
              captured.
            </p>
          )}
        </Panel>
        {!demo && capturing && s?.interface === "vcan0" && (
          <Panel
            title="Traffic Simulation Control"
            aside={<span className="text-xs text-muted-foreground">vcan0 only</span>}
            className="md:col-span-2 xl:col-span-1"
          >
            <p className="text-xs leading-relaxed text-muted-foreground">
              Run legitimate and malicious CAN generators simultaneously. Automated response
              terminates only the malicious simulator process while normal traffic flows
              continuously.
            </p>

            {/* Normal Traffic Controls */}
            <div className="mt-4 rounded-lg border border-border/60 bg-secondary/30 p-3">
              <div className="flex items-center justify-between mb-2">
                <span className="text-xs font-semibold uppercase tracking-wider text-muted-foreground flex items-center gap-1.5">
                  <Activity className="size-3.5 text-emerald-500" /> Normal Traffic
                </span>
                <span
                  className={cn(
                    "text-[0.68rem] font-mono font-semibold px-1.5 py-0.5 rounded border",
                    isNormalRunning
                      ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-400"
                      : "border-border/60 bg-secondary/60 text-muted-foreground",
                  )}
                >
                  {isNormalRunning
                    ? `RUNNING (PID ${s?.normal?.pid ?? "—"})`
                    : (s?.normal?.state ?? "NOT_STARTED")}
                </span>
              </div>
              <p className="text-[0.7rem] text-muted-foreground mb-3">
                Transmits RPM (0x100), Speed (0x101), and Coolant (0x102) frames.
              </p>
              <div className="flex flex-wrap gap-2">
                <Button
                  size="sm"
                  variant={isNormalRunning ? "secondary" : "default"}
                  onClick={onStartNormal}
                  disabled={startNormal.isPending || isNormalRunning || !capturing}
                >
                  {startNormal.isPending ? (
                    <Loader2 className="animate-spin" />
                  ) : (
                    <Play className="size-3.5" />
                  )}{" "}
                  Start Normal Traffic
                </Button>
                <Button
                  size="sm"
                  variant="outline"
                  onClick={onStopNormal}
                  disabled={stopNormal.isPending || !isNormalRunning}
                >
                  {stopNormal.isPending ? (
                    <Loader2 className="animate-spin" />
                  ) : (
                    <Square className="size-3.5" />
                  )}{" "}
                  Stop Normal Traffic
                </Button>
              </div>
            </div>

            {/* Malicious Attack Controls */}
            <div className="mt-3 rounded-lg border border-border/60 bg-secondary/30 p-3">
              <div className="flex items-center justify-between mb-2">
                <span className="text-xs font-semibold uppercase tracking-wider text-muted-foreground flex items-center gap-1.5">
                  <Zap className="size-3.5 text-amber-500" /> Attack Simulator
                </span>
                <span
                  className={cn(
                    "text-[0.68rem] font-mono font-semibold px-1.5 py-0.5 rounded border",
                    isAttackRunning
                      ? "border-destructive/30 bg-destructive/10 text-destructive animate-pulse"
                      : "border-border/60 bg-secondary/60 text-muted-foreground",
                  )}
                >
                  {isAttackRunning
                    ? `RUNNING (Mode ${s?.attack?.mode ?? attackMode})`
                    : (s?.attack?.state ?? "NOT_STARTED")}
                </span>
              </div>
              <div className="mb-2 flex flex-wrap gap-2">
                <Button
                  size="sm"
                  variant={attackMode === 1 ? "default" : "outline"}
                  onClick={() => setAttackMode(1)}
                  disabled={attack.isPending || isAttackRunning}
                >
                  Mode 1 · Flood
                </Button>
                <Button
                  size="sm"
                  variant={attackMode === 2 ? "default" : "outline"}
                  onClick={() => setAttackMode(2)}
                  disabled={attack.isPending || isAttackRunning}
                >
                  Mode 2 · Extended ID
                </Button>
              </div>
              <div className="flex flex-wrap gap-2">
                <Button
                  size="sm"
                  variant="destructive"
                  onClick={onStartAttack}
                  disabled={
                    attack.isPending ||
                    isAttackRunning ||
                    s?.recovery?.state === "ATTACK_STOPPED_VERIFYING"
                  }
                >
                  {attack.isPending ? (
                    <Loader2 className="animate-spin" />
                  ) : (
                    <Zap className="size-3.5" />
                  )}{" "}
                  Start Attack Traffic
                </Button>
              </div>
            </div>

            {/* Global Simulation Stop */}
            <div className="mt-3">
              <Button
                size="sm"
                variant="outline"
                className="w-full text-xs text-muted-foreground hover:text-destructive"
                onClick={onStopAllSimulations}
                disabled={stopSimulations.isPending || (!isNormalRunning && !isAttackRunning)}
              >
                {stopSimulations.isPending ? (
                  <Loader2 className="animate-spin" />
                ) : (
                  <AlertOctagon className="size-3.5" />
                )}{" "}
                Stop All Simulations
              </Button>
            </div>

            {/* Telemetry and Recovery Status */}
            <dl className="mt-3 space-y-2 font-mono text-xs border-t border-border/40 pt-3">
              <Row
                k="normal generator"
                v={
                  <span
                    className={cn(
                      isNormalRunning
                        ? "text-emerald-500 font-semibold"
                        : "text-muted-foreground",
                    )}
                  >
                    {isNormalRunning
                      ? `ACTIVE (PID ${s?.normal?.pid ?? "—"})`
                      : (s?.normal?.state ?? "NOT_STARTED")}
                  </span>
                }
              />
              <Row
                k="attack simulator"
                v={
                  <span
                    className={cn(
                      isAttackRunning
                        ? "text-destructive font-semibold"
                        : "text-muted-foreground",
                    )}
                  >
                    {isAttackRunning
                      ? `ACTIVE (Mode ${s?.attack?.mode ?? attackMode})`
                      : (s?.attack?.state ?? "NOT_STARTED")}
                  </span>
                }
              />
              <Row
                k="concurrent state"
                v={
                  isNormalRunning && isAttackRunning ? (
                    <span className="text-amber-400 font-semibold">
                      CONCURRENT (Normal + Attack)
                    </span>
                  ) : isNormalRunning ? (
                    <span className="text-emerald-400">Normal Only</span>
                  ) : isAttackRunning ? (
                    <span className="text-destructive">Attack Only</span>
                  ) : (
                    <span className="text-muted-foreground">Idle</span>
                  )
                }
              />
              <Row k="recovery state" v={s?.recovery?.state ?? "NOT_STARTED"} />
              <Row
                k="normal windows"
                v={`${s?.recovery?.normal_windows ?? 0} / ${s?.recovery?.required_normal_windows ?? 2}`}
              />
            </dl>
            {s?.recovery?.state === "RECOVERED" && (
              <p className="mt-3 text-xs text-success">
                {s.recovery.required_normal_windows ?? 2} consecutive normal model windows
                observed after the simulator stopped. Legitimate traffic was maintained throughout
                recovery.
              </p>
            )}
            {s?.recovery?.state === "ATTACK_STOPPED_VERIFYING" && (
              <p className="mt-3 text-xs text-warning">
                Attack simulator stopped automatically. Waiting for{" "}
                {s.recovery.required_normal_windows ?? 2} consecutive normal windows while
                legitimate traffic flows…
              </p>
            )}
          </Panel>
        )}
      </div>

      {/* Main Monitoring Dashboard — occupies full available horizontal width */}
      <div className="w-full space-y-6">
          {/* Phase 6: Threat Monitoring Panel */}
          <ThreatMonitoringPanel
            windows={windows}
            incidents={confirmedIncidents}
            capturing={capturing}
            onOpenAlertModal={(inc) => {
              setActiveIncident(inc);
              setIsAlertModalOpen(true);
            }}
            onOpenReport={(inc) => {
              setSelectedReportIncident(inc);
              setIsReportModalOpen(true);
            }}
          />

          {confirmedIncidents.length > 0 && (
            <div className="surface flex flex-wrap items-center justify-between gap-3 border-l-4 border-l-destructive bg-destructive/10 p-4">
              <div className="flex items-center gap-3">
                <ShieldAlert className="size-5 shrink-0 text-destructive" />
                <div>
                  <div className="font-semibold text-sm text-foreground">
                    Confirmed Security Incident:{" "}
                    {confirmedIncidents[confirmedIncidents.length - 1]?.incident_id ?? "—"}
                  </div>
                  <div className="text-xs text-muted-foreground">
                    {confirmedIncidents.length} incident{confirmedIncidents.length > 1 ? "s" : ""}{" "}
                    confirmed by backend Isolation Forest
                  </div>
                </div>
              </div>
              <div className="flex flex-wrap gap-2">
                <Button
                  size="sm"
                  variant="outline"
                  className="text-xs"
                  onClick={() => {
                    const last = confirmedIncidents[confirmedIncidents.length - 1];
                    if (last) {
                      setSelectedReportIncident(last);
                      setIsReportModalOpen(true);
                    }
                  }}
                >
                  Investigation Report
                </Button>
                <Button
                  size="sm"
                  variant="destructive"
                  onClick={() => {
                    const last = confirmedIncidents[confirmedIncidents.length - 1];
                    if (last) {
                      setActiveIncident(last);
                      setIsAlertModalOpen(true);
                    }
                  }}
                >
                  View SOC Alert
                </Button>
              </div>
            </div>
          )}

          {capturing && (
            <div
              className={cn(
                "surface relative flex items-center gap-4 overflow-hidden px-5 py-4 transition-all",
                recentAlert && "surface-alert",
              )}
            >
              <span
                className={cn(
                  "size-2.5 rounded-full animate-pulse-dot",
                  recentAlert ? "bg-destructive" : "bg-success",
                )}
              />
              <div className="flex-1">
                <div className="font-display text-lg font-semibold">
                  {recentAlert ? "Anomalous traffic detected" : "Bus traffic within baseline"}
                </div>
                <div className="text-xs text-muted-foreground">
                  {windows.length} windows scored · {anomalies} anomalous · window #
                  {s?.pending_window_index ?? 0} pending
                </div>
              </div>
              {recentAlert && <ShieldAlert className="size-6 text-destructive" />}
              <div className="pointer-events-none absolute inset-x-0 bottom-0 h-px overflow-hidden">
                <div
                  className={cn(
                    "h-px w-1/3 animate-sweep",
                    recentAlert ? "bg-destructive" : "bg-primary",
                  )}
                />
              </div>
            </div>
          )}

          <MetricGrid
            metrics={
              s
                ? {
                    total: windows.length,
                    normal: windows.length - anomalies,
                    anomalies,
                    rate: windows.length ? (anomalies / windows.length) * 100 : 0,
                  }
                : null
            }
          />

          {/* Phase 6: Real-Time CAN Traffic Monitoring */}
          <RealTimeTrafficMonitor
            windows={windows}
            capturing={capturing}
            pendingWindowIndex={s?.pending_window_index}
          />

          {session.isError && <ErrorState error={session.error} />}

          {/* Combined CAN Bus Activity wave + Threat score analysis panel with clear subheaders */}
          <Panel title="CAN Bus Activity & Threat Analysis" aside={<DemoBadge source={s?.data_source} />}>
            {s && (
              <div className="-mx-5 -mt-2 mb-4 border-b border-border/40 pb-3">
                <BusActivityWave
                  className="rounded-none border-0 bg-transparent"
                  source={{
                    kind: "live",
                    windows,
                    pendingWindowIndex: s.pending_window_index,
                    dataSource: s.data_source,
                    capturing,
                  }}
                  height={120}
                />
              </div>
            )}
            <div className="mb-2 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
              Threat Score Over Time (Isolation Forest)
            </div>
            {windows.length ? (
              <ThreatChart windows={windows} height={260} />
            ) : (
              <EmptyState
                title={
                  capturing
                    ? "Waiting for a completed window…"
                    : "Start a capture to stream results"
                }
              />
            )}
          </Panel>

          <Panel
            title="Detection matrix"
            aside={
              <span className="text-xs text-muted-foreground">
                newest first · click a row for features
              </span>
            }
          >
            {windows.length ? (
              <DetectionTable windows={windows} newestFirst maxHeight={420} />
            ) : (
              <EmptyState title="No windows scored yet" />
            )}
          </Panel>

          <AttackPreventionAnalytics analytics={attackAnalytics} capturing={capturing} />

          {/* Phase 7: Response Validation & Resilience Testing */}
          <ResponseReliabilityDashboard session={s ?? null} capturing={capturing} />

          <SecurityEventTimeline events={timelineEvents} capturing={capturing} />

          <Panel
            title="Incident History & Investigation Reports"
            aside={
              <span className="text-xs text-muted-foreground">
                {confirmedIncidents.length + (allIncidents.data?.length ?? 0)} total incidents
                recorded
              </span>
            }
          >
            <IncidentHistoryTable
              liveIncidents={confirmedIncidents}
              historicIncidents={allIncidents.data ?? []}
            />
          </Panel>
        </div>

        <SecurityAlertModal
          incident={activeIncident}
          session={s ?? null}
          isOpen={isAlertModalOpen}
          onClose={handleCloseAlertModal}
          onOpenAnalysis={handleOpenAnalysis}
          onOpenReport={(inc) => {
            setSelectedReportIncident(inc);
            setIsReportModalOpen(true);
          }}
        />

        <IncidentReportModal
          incident={selectedReportIncident}
          isOpen={isReportModalOpen}
          onClose={() => setIsReportModalOpen(false)}
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
