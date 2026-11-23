import { describe, expect, it, vi } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import { SocOverviewDashboard } from "@/components/app/SocOverviewDashboard";
import { RealTimeTrafficMonitor } from "@/components/app/RealTimeTrafficMonitor";
import { ThreatMonitoringPanel } from "@/components/app/ThreatMonitoringPanel";
import { SystemHealthMonitor } from "@/components/app/SystemHealthMonitor";
import type { InferenceWindow, LiveIncident, LiveSession, SystemStatus } from "@/lib/api/schemas";

// Mock Recharts ResponsiveContainer to render children reliably in tests
vi.mock("recharts", async () => {
  const original = await vi.importActual<Record<string, any>>("recharts");
  return {
    ...original,
    ResponsiveContainer: ({ children }: { children: React.ReactNode }) => (
      <div style={{ width: 500, height: 300 }}>{children}</div>
    ),
  };
});

const sampleWindows: InferenceWindow[] = [
  {
    window_index: 0,
    window_start_utc: "2026-11-10T01:00:00.000Z",
    prediction: "NORMAL",
    anomaly_score: -0.1245,
    features: {
      total_frames: 100,
      unique_can_ids: 3,
      extended_frame_count: 0,
      unique_payload_count: 10,
      max_id_share_pct: 40.0,
      id_0x100_count: 40,
      id_0x100_share_pct: 40.0,
      id_0x101_count: 30,
      id_0x101_share_pct: 30.0,
      id_0x102_count: 30,
      id_0x102_share_pct: 30.0,
      id_0x999_count: 0,
      id_0x999_share_pct: 0.0,
      other_id_count: 0,
      other_id_share_pct: 0.0,
      mean_dlc: 8.0,
      mean_payload_entropy: 2.1,
    },
  },
  {
    window_index: 1,
    window_start_utc: "2026-11-10T01:00:01.000Z",
    prediction: "ANOMALY",
    anomaly_score: 0.7812,
    features: {
      total_frames: 650,
      unique_can_ids: 4,
      extended_frame_count: 50,
      unique_payload_count: 15,
      max_id_share_pct: 75.0,
      id_0x100_count: 500,
      id_0x100_share_pct: 76.9,
      id_0x101_count: 30,
      id_0x101_share_pct: 4.6,
      id_0x102_count: 30,
      id_0x102_share_pct: 4.6,
      id_0x999_count: 50,
      id_0x999_share_pct: 7.7,
      other_id_count: 40,
      other_id_share_pct: 6.2,
      mean_dlc: 8.0,
      mean_payload_entropy: 3.5,
    },
  },
];

const sampleIncident: LiveIncident = {
  incident_id: "INC-0001",
  severity: "HIGH",
  status: "CONFIRMED",
  analysis_id: "analysis_live_incident_0001",
  analysis_registered: true,
  start_window: 1,
  end_window: 1,
  window_count: 1,
  start_time_utc: "2026-11-10T01:00:01.000Z",
  end_time_utc: "2026-11-10T01:00:01.000Z",
  affected_can_ids: ["0x100", "0x999"],
  summary: "High frequency flood attack with unexpected extended CAN ID frames",
  reasons: [
    {
      code: "HIGH_TRAFFIC_VOLUME",
      message: "Frame count 650 exceeds nominal threshold",
      evidence: { frame_count: 650 },
    },
  ],
  response_evidence: {
    can_id_counts: { "0x100": 500, "0x999": 50 },
    unexpected_can_ids: ["0x999"],
    dominant_can_id: "0x100",
    dominant_can_id_share_pct: 76.9,
  },
  windows: [sampleWindows[1]],
  mitigation: {
    attempted: true,
    succeeded: true,
    action: "TERMINATE_ATTACK_PROCESS",
    target_pid: 12345,
    return_code: 0,
    timestamp_utc: "2026-11-10T01:00:02.000Z",
  },
};

const sampleSession: LiveSession = {
  id: "session_live_test_1",
  interface: "vcan0",
  state: "capturing",
  data_source: "vcan0",
  start_time_utc: "2026-11-10T01:00:00.000Z",
  sniffer_pid: 10001,
  pending_window_index: 2,
  windows: sampleWindows,
  incidents: [sampleIncident],
  normal: {
    state: "RUNNING",
    pid: 20002,
    exit_code: null,
  },
  attack: {
    state: "STOPPED",
    mode: 1,
    pid: 12345,
    exit_code: 0,
  },
  attack_history: [
    {
      attempt_id: 1,
      mode: 1,
      pid: 12345,
      state: "STOPPED",
      start_time_utc: "2026-11-10T01:00:00.500Z",
      stop_time_utc: "2026-11-10T01:00:02.000Z",
      stopped_by: "AUTO_DEFENSE",
      return_code: 0,
      incident_id: "INC-0001",
    },
  ],
  recovery: {
    state: "RECOVERED",
    normal_windows: 2,
    required_normal_windows: 2,
  },
};

const sampleStatus: SystemStatus = {
  interface: {
    name: "vcan0",
    state: "UP",
    rx_packets: 12000,
    tx_packets: 12000,
  },
  sniffer: {
    path: "/bin/can_sniffer",
    built: true,
  },
  model: {
    loaded: true,
    path: "model.joblib",
    algorithm: "IsolationForest",
    contamination: 0.05,
    feature_columns: ["total_frames", "extended_frame_count"],
  },
  backend_version: "1.0.0",
  data_source: "vcan0",
};

describe("Phase 6: Advanced SOC Dashboard & Real-Time Monitoring", () => {
  describe("SocOverviewDashboard", () => {
    it("renders executive summary metrics based on actual backend data", () => {
      render(
        <SocOverviewDashboard
          session={sampleSession}
          status={sampleStatus}
          totalHistoricalIncidents={1}
        />,
      );

      // Section title
      expect(screen.getByText("SOC Live Operations Overview")).toBeInTheDocument();

      // Confirmed incidents
      expect(screen.getByText("Confirmed Incidents")).toBeInTheDocument();
      expect(screen.getByText("Active Attacks")).toBeInTheDocument();
      expect(screen.getByText("Attempts Stopped")).toBeInTheDocument();
      expect(screen.getByText("Confirmed Mitigations")).toBeInTheDocument();

      // Normal traffic status
      expect(screen.getByText("Normal Traffic")).toBeInTheDocument();
      expect(screen.getByText(/PID 20002/)).toBeInTheDocument();

      // Monitoring & recovery status
      expect(screen.getByText("Monitoring State")).toBeInTheDocument();
      expect(screen.getByText(/RECOVERED/)).toBeInTheDocument();
    });

    it("displays appropriate idle values when session is null", () => {
      render(
        <SocOverviewDashboard
          session={null}
          status={sampleStatus}
          totalHistoricalIncidents={0}
        />,
      );

      expect(screen.getByText("MONITORING STANDBY")).toBeInTheDocument();
      expect(screen.getByText("IDLE")).toBeInTheDocument();
      expect(screen.getAllByText("NOT_STARTED").length).toBeGreaterThan(0);
    });

    it("verifies mitigations only count when return_code === 0", () => {
      const sessionFailedMitigation: LiveSession = {
        ...sampleSession,
        attack_history: [
          {
            attempt_id: 1,
            mode: 1,
            pid: 12345,
            state: "STOPPED",
            start_time_utc: "2026-11-10T01:00:00.500Z",
            stop_time_utc: "2026-11-10T01:00:02.000Z",
            stopped_by: "AUTO_DEFENSE",
            return_code: 1, // non-zero indicates failure or unverified
            incident_id: "INC-0001",
          },
        ],
      };

      render(
        <SocOverviewDashboard
          session={sessionFailedMitigation}
          status={sampleStatus}
          totalHistoricalIncidents={1}
        />,
      );

      // Check card texts
      expect(screen.getByText("Attempts Stopped")).toBeInTheDocument();
      expect(screen.getByText("Confirmed Mitigations")).toBeInTheDocument();
      expect(screen.getByText(/0\/1 clean exits \(rc=0\)/)).toBeInTheDocument();
    });
  });

  describe("RealTimeTrafficMonitor", () => {
    it("renders FPS throughput, standard vs extended frame counts, and distribution", () => {
      render(
        <RealTimeTrafficMonitor
          windows={sampleWindows}
          capturing={true}
          pendingWindowIndex={2}
        />,
      );

      expect(screen.getByText("Real-Time CAN Traffic Monitoring")).toBeInTheDocument();
      expect(screen.getByText("Current Throughput")).toBeInTheDocument();
      expect(screen.getByText("Peak Bus Load")).toBeInTheDocument();
      expect(screen.getByText("Average Cadence")).toBeInTheDocument();
      expect(screen.getByText("Extended 29-bit")).toBeInTheDocument();

      // Legend items
      expect(screen.getByText("Standard CAN")).toBeInTheDocument();
      expect(screen.getAllByText("Extended (29-bit)").length).toBeGreaterThan(0);
      expect(screen.getByText("Anomaly Window")).toBeInTheDocument();

      // ID distribution
      expect(screen.getByText("Traffic Distribution by CAN Arbitration ID (Latest Window)")).toBeInTheDocument();
      expect(screen.getAllByText(/0x100/).length).toBeGreaterThan(0);
      expect(screen.getByText("0x101")).toBeInTheDocument();
      expect(screen.getByText("0x102")).toBeInTheDocument();
      expect(screen.getByText("0x999")).toBeInTheDocument();

      // Clear disclaimer distinguishing measured data from estimated attribution
      expect(screen.getByText("Measured Data vs. Estimated Attribution Policy")).toBeInTheDocument();
      expect(screen.getByText(/shared between the legitimate RPM generator and the flood adversary/)).toBeInTheDocument();
    });

    it("handles empty windows gracefully without crashing", () => {
      render(
        <RealTimeTrafficMonitor
          windows={[]}
          capturing={false}
          pendingWindowIndex={null}
        />,
      );

      expect(screen.getByText("Real-Time CAN Traffic Monitoring")).toBeInTheDocument();
      expect(screen.getByText("Start capture to visualize live traffic volume")).toBeInTheDocument();
    });
  });

  describe("ThreatMonitoringPanel", () => {
    it("renders nominal baseline when no incidents or anomalies are present", () => {
      render(
        <ThreatMonitoringPanel
          windows={[sampleWindows[0]]}
          incidents={[]}
          capturing={true}
        />,
      );

      expect(screen.getByText("Active Threat Monitoring")).toBeInTheDocument();
      expect(screen.getByText("Nominal Baseline")).toBeInTheDocument();
      expect(screen.getByText("Traffic Within Specification")).toBeInTheDocument();
    });

    it("renders detected incident, anomaly score, and actions when incident occurs", () => {
      const onOpenAlert = vi.fn();
      const onOpenReport = vi.fn();

      render(
        <ThreatMonitoringPanel
          windows={sampleWindows}
          incidents={[sampleIncident]}
          capturing={true}
          onOpenAlertModal={onOpenAlert}
          onOpenReport={onOpenReport}
        />,
      );

      expect(screen.getByText("Active Threat Monitoring")).toBeInTheDocument();
      expect(screen.getByText("INC-0001")).toBeInTheDocument();

      // Action buttons
      const alertBtn = screen.getByRole("button", { name: /View SOC Alert/i });
      fireEvent.click(alertBtn);
      expect(onOpenAlert).toHaveBeenCalledWith(sampleIncident);

      const reportBtn = screen.getByRole("button", { name: /Investigation Report/i });
      fireEvent.click(reportBtn);
      expect(onOpenReport).toHaveBeenCalledWith(sampleIncident);
    });
  });

  describe("SystemHealthMonitor", () => {
    it("monitors all 6 subsystems accurately with RUNNING, STOPPED, ERROR, NOT CONFIGURED states", () => {
      render(
        <SystemHealthMonitor
          status={sampleStatus}
          session={sampleSession}
          isStatusError={false}
        />,
      );

      expect(screen.getByText("System Health & Subsystem Telemetry")).toBeInTheDocument();
      expect(screen.getByText("CAN Bus Interface")).toBeInTheDocument();
      expect(screen.getByText("CAN Sniffer Daemon")).toBeInTheDocument();
      expect(screen.getByText("Normal Traffic Generator")).toBeInTheDocument();
      expect(screen.getByText("Attack Simulator")).toBeInTheDocument();
      expect(screen.getByText("Backend API Service")).toBeInTheDocument();
      expect(screen.getByText("ML Detection Pipeline")).toBeInTheDocument();

      // Operational state checks
      expect(screen.getAllByText("RUNNING").length).toBeGreaterThan(0);
      expect(screen.getAllByText("STOPPED").length).toBeGreaterThan(0);
    });

    it("flags ERROR correctly when backend connection fails", () => {
      render(
        <SystemHealthMonitor
          status={undefined}
          session={null}
          isStatusError={true}
        />,
      );

      expect(screen.getAllByText("ERROR").length).toBeGreaterThan(0);
      expect(screen.getByText("Cannot connect to backend server")).toBeInTheDocument();
    });

    it("flags NOT CONFIGURED correctly when model is missing", () => {
      const missingModelStatus: SystemStatus = {
        ...sampleStatus,
        model: {
          ...sampleStatus.model,
          loaded: false,
          algorithm: "",
        },
      };

      render(
        <SystemHealthMonitor
          status={missingModelStatus}
          session={null}
          isStatusError={false}
        />,
      );

      expect(screen.getAllByText("NOT CONFIGURED").length).toBeGreaterThan(0);
      expect(screen.getByText(/Model file missing/)).toBeInTheDocument();
    });
  });
});
