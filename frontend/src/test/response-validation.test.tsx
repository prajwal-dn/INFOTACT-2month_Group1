import { describe, expect, it, vi } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import { ResponseReliabilityDashboard } from "@/components/app/ResponseReliabilityDashboard";
import type { LiveSession, ResilienceScenarioResult } from "@/lib/api/schemas";

// Mock queries
vi.mock("@/lib/api/queries", () => ({
  useResilienceScenarios: () => ({
    data: [
      {
        scenario_id: "SCN-01",
        scenario_name: "Attack simulator exits unexpectedly",
        expected_behavior: "Reconcile process crash with non-zero exit code; mark state STOPPED (PROCESS_CRASH).",
        actual_result: "Reconciled to state=STOPPED, return_code=139, reason=PROCESS_CRASH",
        timestamp: "2026-11-10T02:00:00Z",
        status: "PASS",
        diagnostic_evidence: { initial_pid: 7711, return_code: 139 },
      },
      {
        scenario_id: "SCN-02",
        scenario_name: "Attack simulator does not terminate within configured timeout",
        expected_behavior: "Escalate signal termination from SIGINT/SIGTERM to SIGKILL upon timeout.",
        actual_result: "Signal escalation executed; final return_code=-9",
        timestamp: "2026-11-10T02:00:01Z",
        status: "PASS",
        diagnostic_evidence: { target_pid: 8822, final_return_code: -9 },
      },
      {
        scenario_id: "SCN-03",
        scenario_name: "Normal traffic generator crashes",
        expected_behavior: "Reconcile normal crash with return_code=1; sniffer continues capturing uninterrupted.",
        actual_result: "Normal state reconciled to STOPPED (rc=1, PROCESS_CRASH); sniffer active",
        timestamp: "2026-11-10T02:00:02Z",
        status: "PASS",
        diagnostic_evidence: { normal_pid: 3311, normal_return_code: 1 },
      },
      {
        scenario_id: "SCN-04",
        scenario_name: "Sniffer process stops unexpectedly",
        expected_behavior: "Detect sniffer exit; reconcile sniffer availability as inactive.",
        actual_result: "Sniffer termination detected; sniffer_active=false, exit_code=2",
        timestamp: "2026-11-10T02:00:03Z",
        status: "PASS",
        diagnostic_evidence: { sniffer_pid: 1101, exit_code: 2 },
      },
      {
        scenario_id: "SCN-05",
        scenario_name: "Backend API becomes unavailable",
        expected_behavior: "Catch connection failure, flag ERROR status in SystemHealthMonitor.",
        actual_result: "Gracefully intercepted backend connection outage: ConnectionRefusedError",
        timestamp: "2026-11-10T02:00:04Z",
        status: "PASS",
        diagnostic_evidence: { handled_gracefully: true },
      },
      {
        scenario_id: "SCN-06",
        scenario_name: "Recovery verification does not complete",
        expected_behavior: "Reset consecutive normal window counter to 0 upon intermediate anomaly.",
        actual_result: "Anomaly during verification reset normal_windows to 0; state remained ATTACK_STOPPED_VERIFYING",
        timestamp: "2026-11-10T02:00:05Z",
        status: "PASS",
        diagnostic_evidence: { normal_windows: 0 },
      },
      {
        scenario_id: "SCN-07",
        scenario_name: "Multiple incidents occur in succession",
        expected_behavior: "Correctly process and register successive incidents with distinct IDs.",
        actual_result: "Generated 2 distinct incidents: ['INC-0001', 'INC-0002']",
        timestamp: "2026-11-10T02:00:06Z",
        status: "PASS",
        diagnostic_evidence: { incident_ids: ["INC-0001", "INC-0002"] },
      },
      {
        scenario_id: "SCN-08",
        scenario_name: "Session stops while an incident is being processed",
        expected_behavior: "Gracefully drain queued incident jobs, complete incident registration, and shutdown.",
        actual_result: "Shutdown completed=true; queue empty=true; incident registered=true",
        timestamp: "2026-11-10T02:00:07Z",
        status: "PASS",
        diagnostic_evidence: { shutdown_complete: true },
      },
    ],
    isLoading: false,
    isError: false,
  }),
  useRunResilienceScenarios: () => ({
    mutate: vi.fn(),
    isPending: false,
  }),
}));

const sampleSessionWithMitigation: LiveSession = {
  id: "session_phase7_test",
  data_source: "vcan0",
  state: "capturing",
  interface: "vcan0",
  capture_file: "/data/capture.csv",
  started_at: "2026-11-10T02:00:00Z",
  frames_captured: 12000,
  windows: [],
  pending_window_index: 5,
  message: null,
  incidents: [
    {
      incident_id: "INC-0001",
      severity: "HIGH",
      status: "RECOVERED",
      start_window: 1,
      end_window: 2,
      window_count: 2,
      start_time_utc: "2026-11-10T02:00:01Z",
      end_time_utc: "2026-11-10T02:00:02Z",
      affected_can_ids: ["0x100"],
      reasons: [],
      windows: [],
      summary: "High frequency flood",
      response_latency: {
        first_anomalous_window_utc: "2026-11-10T02:00:01Z",
        incident_confirmed_utc: "2026-11-10T02:00:02Z",
        response_initiated_utc: "2026-11-10T02:00:02.100Z",
        attack_terminated_utc: "2026-11-10T02:00:02.145Z",
        detection_ms: 1000,
        mitigation_ms: 45,
        detection_to_termination_ms: 1045,
      },
    },
  ],
  normal: {
    state: "RUNNING",
    pid: 4401,
  },
  attack: {
    state: "STOPPED",
    mode: 1,
    pid: 9902,
    exit_code: 0,
    return_code: 0,
  },
  recovery: {
    state: "RECOVERED",
    normal_windows: 2,
    required_normal_windows: 2,
  },
  attack_history: [
    {
      attack_id: "att_1",
      mode: 1,
      pid: 9902,
      state: "STOPPED",
      started_at: "2026-11-10T02:00:00Z",
      stopped_at: "2026-11-10T02:00:02Z",
      return_code: 0,
      termination_reason: "AUTOMATIC_RESPONSE",
      incident_id: "INC-0001",
    },
  ],
  response_audit_trail: [
    {
      audit_id: "resp_test1",
      incident_id: "INC-0001",
      response_action: "TERMINATE_ATTACK_PROCESS",
      process_pid: 9902,
      action_initiation_timestamp: "2026-11-10T02:00:02.100Z",
      process_termination_timestamp: "2026-11-10T02:00:02.145Z",
      return_code: 0,
      termination_reason: "AUTOMATIC_RESPONSE",
      sniffer_continuity_status: "PASS",
      normal_traffic_continuity_status: "PASS",
      recovery_verification_result: "PASS",
      final_response_status: "VERIFIED_RECOVERED",
      detection_latency_ms: 1000,
      mitigation_latency_ms: 45,
      total_latency_ms: 1045,
    },
  ],
  response_validation: {
    overall_status: "PASS",
    checks: {
      confirmed_incident_creation: { status: "PASS", detail: "1 confirmed incident(s) generated" },
      automated_response_initiation: { status: "PASS", detail: "1 automated response initiated" },
      attack_simulator_termination: { status: "PASS", detail: "1 attack process(es) terminated" },
      actual_process_exit_status: { status: "PASS", detail: "All 1 process(es) confirmed exit code 0" },
      sniffer_process_continuity: { status: "PASS", detail: "Sniffer active (PID 1001, 12000 frames)" },
      normal_traffic_continuity: { status: "PASS", detail: "Normal traffic running continuously (PID 4401)" },
      recovery_verification: { status: "PASS", detail: "Recovery verified (2/2 consecutive normal windows)" },
    },
  },
  response_reliability: {
    total_response_attempts: 1,
    confirmed_successful_mitigations: 1,
    failed_mitigations: 0,
    unexpected_attack_process_exits: 0,
    recovery_verification_success_rate: 100.0,
    average_detection_latency_ms: 1000.0,
    average_mitigation_latency_ms: 45.0,
    average_recovery_duration_ms: null,
  },
};

describe("Phase 7: Automated Response Validation & Resilience Testing", () => {
  it("renders all 7 validation steps with explicit PASS badges and strict exit status check", () => {
    render(<ResponseReliabilityDashboard session={sampleSessionWithMitigation} capturing={true} />);

    expect(screen.getByText("Automated Response Validation Lifecycle")).toBeInTheDocument();
    expect(screen.getByText("Confirmed Security Incident Creation")).toBeInTheDocument();
    expect(screen.getByText("Automated Response Initiation")).toBeInTheDocument();
    expect(screen.getByText("Attack Simulator Termination")).toBeInTheDocument();
    expect(screen.getByText("Actual Process Exit Status (rc == 0)")).toBeInTheDocument();
    expect(screen.getByText("Sniffer Process Continuity")).toBeInTheDocument();
    expect(screen.getByText("Normal Traffic Generator Continuity")).toBeInTheDocument();
    expect(screen.getByText("Consecutive Normal-Window Recovery Verification")).toBeInTheDocument();

    // Overall status
    expect(screen.getByText(/LIFECYCLE: PASS/)).toBeInTheDocument();
  });

  it("renders response reliability analytics and clearly labels unavailable metrics", () => {
    render(<ResponseReliabilityDashboard session={sampleSessionWithMitigation} capturing={true} />);

    expect(screen.getByText("Response Reliability Analytics")).toBeInTheDocument();
    expect(screen.getByText("Total Attempts")).toBeInTheDocument();
    expect(screen.getByText("Confirmed Stops")).toBeInTheDocument();
    expect(screen.getByText("Failed Mitigations")).toBeInTheDocument();
    expect(screen.getByText("Unexpected Exits")).toBeInTheDocument();
    expect(screen.getByText("Recovery Success")).toBeInTheDocument();
    expect(screen.getByText("100.0%")).toBeInTheDocument();
    expect(screen.getByText("Avg Detection")).toBeInTheDocument();
    expect(screen.getByText("Avg Mitigation")).toBeInTheDocument();

    // Unavailable metrics check
    expect(screen.getByText("Recovery Duration")).toBeInTheDocument();
    expect(screen.getAllByText("UNAVAILABLE").length).toBeGreaterThan(0);
  });

  it("renders the structured response audit trail with process PID, timestamps, and return code", () => {
    render(<ResponseReliabilityDashboard session={sampleSessionWithMitigation} capturing={true} />);

    expect(screen.getByText("Automated Response Audit Trail")).toBeInTheDocument();
    expect(screen.getByText("INC-0001")).toBeInTheDocument();
    expect(screen.getByText("TERMINATE_ATTACK_PROCESS")).toBeInTheDocument();
    expect(screen.getByText("9902")).toBeInTheDocument();
    expect(screen.getByText("rc=0")).toBeInTheDocument();
    expect(screen.getByText("VERIFIED_RECOVERED")).toBeInTheDocument();
  });

  it("renders all 8 controlled failure scenarios and expands diagnostic evidence on click", () => {
    render(<ResponseReliabilityDashboard session={sampleSessionWithMitigation} capturing={true} />);

    expect(screen.getByText("Controlled Failure Scenario Testing")).toBeInTheDocument();
    expect(screen.getByText("Execute Resilience Suite")).toBeInTheDocument();

    // Verify all 8 scenario IDs
    expect(screen.getByText("SCN-01")).toBeInTheDocument();
    expect(screen.getByText("SCN-02")).toBeInTheDocument();
    expect(screen.getByText("SCN-03")).toBeInTheDocument();
    expect(screen.getByText("SCN-04")).toBeInTheDocument();
    expect(screen.getByText("SCN-05")).toBeInTheDocument();
    expect(screen.getByText("SCN-06")).toBeInTheDocument();
    expect(screen.getByText("SCN-07")).toBeInTheDocument();
    expect(screen.getByText("SCN-08")).toBeInTheDocument();

    // Expand Scenario 1
    const scn1Header = screen.getByText("Attack simulator exits unexpectedly");
    fireEvent.click(scn1Header);

    expect(screen.getByText(/Reconciled to state=STOPPED, return_code=139/)).toBeInTheDocument();
    expect(screen.getByText("Diagnostic Evidence:")).toBeInTheDocument();
  });

  it("renders NOT VERIFIED appropriately when session has no incidents or mitigation", () => {
    const emptySession: LiveSession = {
      ...sampleSessionWithMitigation,
      incidents: [],
      attack_history: [],
      response_audit_trail: [],
      response_validation: undefined,
      response_reliability: undefined,
      attack: { state: "NOT_STARTED" },
      normal: { state: "NOT_STARTED" },
      recovery: { state: "NOT_STARTED" },
    };

    render(<ResponseReliabilityDashboard session={emptySession} capturing={false} />);

    expect(screen.getAllByText("NOT VERIFIED").length).toBeGreaterThan(0);
    expect(screen.getByText(/No automated response events recorded/)).toBeInTheDocument();
  });
});
