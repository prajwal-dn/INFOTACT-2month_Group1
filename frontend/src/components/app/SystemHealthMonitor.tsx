/**
 * Phase 6: System Health Monitoring
 *
 * Dedicated SOC telemetry panel monitoring all critical subsystem components:
 * - CAN Interface (vcan0 virtual socketCAN bus)
 * - CAN Sniffer Process (C socket sniffer engine)
 * - Normal Traffic Generator (Legitimate RPM, Speed, Coolant daemon)
 * - Attack Simulator (Adversarial simulation process)
 * - Backend API Connection (FastAPI REST service)
 * - ML Detection Service (Isolation Forest feature extractor & inference)
 *
 * Supported explicit states:
 *   - RUNNING
 *   - STOPPED
 *   - ERROR
 *   - NOT CONFIGURED
 *
 * Never implies an unavailable component is healthy.
 */
import {
  Activity,
  AlertCircle,
  AlertTriangle,
  BrainCircuit,
  CheckCircle2,
  Cpu,
  Layers,
  Network,
  Radio,
  Server,
  XCircle,
  Zap,
} from "lucide-react";

import { Panel } from "@/components/app/primitives";
import type { LiveSession, SystemStatus } from "@/lib/api/schemas";
import { cn } from "@/lib/utils";

export type HealthState = "RUNNING" | "STOPPED" | "ERROR" | "NOT CONFIGURED";

interface SubsystemHealth {
  name: string;
  category: string;
  state: HealthState;
  detail: string;
  icon: React.ReactNode;
  diagnostic: string;
}

interface SystemHealthMonitorProps {
  status: SystemStatus | undefined;
  session: LiveSession | null;
  isStatusError?: boolean;
}

export function SystemHealthMonitor({
  status,
  session,
  isStatusError = false,
}: SystemHealthMonitorProps) {
  const capturing = session?.state === "capturing";

  // 1. CAN interface
  let ifaceState: HealthState = "NOT CONFIGURED";
  let ifaceDetail = "Interface status unavailable";
  let ifaceDiagnostic = "Run 'sudo ip link add dev vcan0 type vcan && sudo ip link set up vcan0'";

  if (isStatusError) {
    ifaceState = "ERROR";
    ifaceDetail = "Backend connection offline";
  } else if (status?.data_source === "demo") {
    ifaceState = "STOPPED";
    ifaceDetail = "Demo virtual interface (simulated)";
    ifaceDiagnostic = "Not connected to Linux kernel socketCAN";
  } else if (status?.interface) {
    if (status.interface.state === "UP") {
      ifaceState = "RUNNING";
      ifaceDetail = `${status.interface.name} is UP (SocketCAN Active)`;
      ifaceDiagnostic = "Kernel link operational on vcan0";
    } else if (status.interface.state === "DOWN") {
      ifaceState = "STOPPED";
      ifaceDetail = `${status.interface.name} is DOWN`;
      ifaceDiagnostic = "Run 'sudo ip link set up vcan0'";
    } else if (status.interface.state === "MISSING") {
      ifaceState = "NOT CONFIGURED";
      ifaceDetail = `${status.interface.name} not found`;
      ifaceDiagnostic = "Interface missing from Linux network namespace";
    } else {
      ifaceState = "ERROR";
      ifaceDetail = `Unknown interface state: ${status.interface.state}`;
    }
  }

  // 2. CAN sniffer process
  let snifferState: HealthState = "NOT CONFIGURED";
  let snifferDetail = "Sniffer binary not inspected";
  let snifferDiagnostic = "Compile with 'make can_sniffer'";

  if (isStatusError) {
    snifferState = "ERROR";
    snifferDetail = "Cannot probe sniffer";
  } else if (status?.data_source === "demo") {
    snifferState = "STOPPED";
    snifferDetail = "Demo mode · sniffer inactive";
    snifferDiagnostic = "Playback generated in frontend memory";
  } else if (capturing) {
    snifferState = "RUNNING";
    snifferDetail = `Process streaming frames (${session?.frames_captured?.toLocaleString() ?? 0} frames)`;
    snifferDiagnostic = "Connected to Unix domain socket /tmp/can_sentinel.sock";
  } else if (status?.sniffer?.built) {
    snifferState = "STOPPED";
    snifferDetail = `Binary built (${status.sniffer.path})`;
    snifferDiagnostic = "Ready to start capture on demand";
  } else if (status?.sniffer && !status.sniffer.built) {
    snifferState = "NOT CONFIGURED";
    snifferDetail = `Binary missing: ${status.sniffer.path}`;
    snifferDiagnostic = "Binary not compiled. Run make in build directory.";
  }

  // 3. Normal traffic generator
  let normalState: HealthState = "NOT CONFIGURED";
  let normalDetail = "Generator not initiated";
  let normalDiagnostic = "Transmits RPM (0x100), Speed (0x101), Coolant (0x102)";

  if (session?.normal) {
    if (session.normal.state === "RUNNING") {
      normalState = "RUNNING";
      normalDetail = `PID ${session.normal.pid ?? "—"} active (${session.normal.interval_ms ?? 20}ms cadence)`;
      normalDiagnostic = "Transmitting nominal CAN matrix frames on vcan0";
    } else if (session.normal.state === "STOPPED") {
      if (session.normal.return_code != null && session.normal.return_code !== 0) {
        normalState = "ERROR";
        normalDetail = `Exited with error code ${session.normal.return_code}`;
        normalDiagnostic = "Generator crashed or terminated abnormally";
      } else {
        normalState = "STOPPED";
        normalDetail = "Generator stopped";
        normalDiagnostic = "Ready to launch via Traffic Simulation Control";
      }
    } else {
      normalState = "NOT CONFIGURED";
      normalDetail = "Generator standby";
    }
  }

  // 4. Attack simulator
  let attackState: HealthState = "NOT CONFIGURED";
  let attackDetail = "Simulator standby";
  let attackDiagnostic = "Adversarial generator for Mode 1 flood or Mode 2 injection";

  if (session?.attack) {
    if (session.attack.state === "RUNNING") {
      attackState = "RUNNING";
      attackDetail = `ACTIVE: Mode ${session.attack.mode ?? 1} (PID ${session.attack.pid ?? "—"})`;
      attackDiagnostic = session.attack.mode === 1 ? "Transmitting high-frequency flood @ 1ms" : "Injecting unauthorized extended ID 0x999";
    } else if (session.attack.state === "STOPPED") {
      attackState = "STOPPED";
      attackDetail = session.attack.return_code === 0 ? "TERMINATED (rc=0 clean exit)" : `STOPPED (rc=${session.attack.return_code ?? "—"})`;
      attackDiagnostic = "Adversary terminated by automated response engine";
    } else {
      attackState = "STOPPED";
      attackDetail = "No attack process active";
    }
  }

  // 5. Backend API connection
  let apiState: HealthState = "NOT CONFIGURED";
  let apiDetail = "Checking FastAPI service…";
  let apiDiagnostic = "http://127.0.0.1:8000/api";

  if (isStatusError) {
    apiState = "ERROR";
    apiDetail = "Cannot connect to backend server";
    apiDiagnostic = "Verify python src/api_server.py is running on port 8000";
  } else if (status?.data_source === "demo") {
    apiState = "RUNNING";
    apiDetail = "Demo Client Active (Simulated API)";
    apiDiagnostic = "Illustrative client-side evaluation";
  } else if (status) {
    apiState = "RUNNING";
    apiDetail = `Connected (FastAPI v${status.backend_version})`;
    apiDiagnostic = "REST & live telemetry services online";
  }

  // 6. ML detection service
  let mlState: HealthState = "NOT CONFIGURED";
  let mlDetail = "Model info unavailable";
  let mlDiagnostic = "Isolation Forest 14-feature multi-dimensional engine";

  if (isStatusError) {
    mlState = "ERROR";
    mlDetail = "Cannot reach detection service";
  } else if (status?.data_source === "demo") {
    mlState = "RUNNING";
    mlDetail = "Demo scoring engine";
    mlDiagnostic = "Illustrative synthetic anomaly profiles";
  } else if (status?.model?.loaded) {
    mlState = "RUNNING";
    mlDetail = `${status.model.algorithm} (1000ms window)`;
    mlDiagnostic = `Contamination: ${status.model.contamination ?? 0.05} · ${status.model.feature_columns?.length ?? 14} features`;
  } else if (status?.model && !status.model.loaded) {
    mlState = "NOT CONFIGURED";
    mlDetail = `Model file missing: ${status.model.path}`;
    mlDiagnostic = "Model bundle must be trained and placed in models/";
  }

  const subsystems: SubsystemHealth[] = [
    {
      name: "CAN Bus Interface",
      category: "Network Link",
      state: ifaceState,
      detail: ifaceDetail,
      diagnostic: ifaceDiagnostic,
      icon: <Network className="size-4" />,
    },
    {
      name: "CAN Sniffer Daemon",
      category: "Capture Engine",
      state: snifferState,
      detail: snifferDetail,
      diagnostic: snifferDiagnostic,
      icon: <Radio className="size-4" />,
    },
    {
      name: "Normal Traffic Generator",
      category: "Nominal ECU",
      state: normalState,
      detail: normalDetail,
      diagnostic: normalDiagnostic,
      icon: <Activity className="size-4" />,
    },
    {
      name: "Attack Simulator",
      category: "Adversary Engine",
      state: attackState,
      detail: attackDetail,
      diagnostic: attackDiagnostic,
      icon: <Zap className="size-4" />,
    },
    {
      name: "Backend API Service",
      category: "REST Controller",
      state: apiState,
      detail: apiDetail,
      diagnostic: apiDiagnostic,
      icon: <Server className="size-4" />,
    },
    {
      name: "ML Detection Pipeline",
      category: "Isolation Forest",
      state: mlState,
      detail: mlDetail,
      diagnostic: mlDiagnostic,
      icon: <BrainCircuit className="size-4" />,
    },
  ];

  return (
    <Panel
      title="System Health & Subsystem Telemetry"
      aside={
        <div className="flex items-center gap-2">
          <span className="text-xs text-muted-foreground font-mono">
            {subsystems.filter((s) => s.state === "RUNNING").length} / {subsystems.length} Running
          </span>
        </div>
      }
    >
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
        {subsystems.map((sub) => (
          <div
            key={sub.name}
            className={cn(
              "rounded-xl border p-3.5 flex flex-col justify-between transition-all",
              sub.state === "RUNNING"
                ? "border-emerald-500/30 bg-secondary/30"
                : sub.state === "ERROR"
                  ? "border-destructive/40 bg-destructive/10"
                  : sub.state === "STOPPED"
                    ? "border-border/60 bg-secondary/20"
                    : "border-border/40 bg-secondary/10"
            )}
          >
            <div>
              <div className="flex items-center justify-between mb-2">
                <div className="flex items-center gap-2">
                  <span className="text-muted-foreground">{sub.icon}</span>
                  <div>
                    <h3 className="text-xs font-semibold text-foreground leading-none">
                      {sub.name}
                    </h3>
                    <span className="text-[0.65rem] text-muted-foreground">
                      {sub.category}
                    </span>
                  </div>
                </div>

                <StateBadge state={sub.state} />
              </div>

              <p className="font-mono text-xs text-foreground font-medium truncate" title={sub.detail}>
                {sub.detail}
              </p>
            </div>

            <p className="mt-2 text-[0.65rem] text-muted-foreground truncate border-t border-border/40 pt-1.5" title={sub.diagnostic}>
              {sub.diagnostic}
            </p>
          </div>
        ))}
      </div>
    </Panel>
  );
}

// ─── Subcomponent: StateBadge ────────────────────────────────────────────────

function StateBadge({ state }: { state: HealthState }) {
  if (state === "RUNNING") {
    return (
      <span className="flex items-center gap-1 rounded border border-emerald-500/30 bg-emerald-500/10 px-1.5 py-0.5 font-mono text-[0.62rem] font-bold text-emerald-400">
        <CheckCircle2 className="size-3" />
        RUNNING
      </span>
    );
  }

  if (state === "STOPPED") {
    return (
      <span className="flex items-center gap-1 rounded border border-border/80 bg-secondary px-1.5 py-0.5 font-mono text-[0.62rem] font-semibold text-muted-foreground">
        <span className="size-1.5 rounded-full bg-muted-foreground" />
        STOPPED
      </span>
    );
  }

  if (state === "ERROR") {
    return (
      <span className="flex items-center gap-1 rounded border border-destructive/40 bg-destructive/15 px-1.5 py-0.5 font-mono text-[0.62rem] font-bold text-destructive">
        <XCircle className="size-3" />
        ERROR
      </span>
    );
  }

  return (
    <span className="flex items-center gap-1 rounded border border-amber-500/30 bg-amber-500/10 px-1.5 py-0.5 font-mono text-[0.62rem] font-semibold text-amber-500">
      <AlertTriangle className="size-3" />
      NOT CONFIGURED
    </span>
  );
}

