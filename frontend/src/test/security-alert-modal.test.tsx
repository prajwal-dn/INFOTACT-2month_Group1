import { render, screen, fireEvent } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import {
  SecurityAlertModal,
  getAttackClassification,
} from "@/components/app/SecurityAlertModal";
import type { LiveIncident, LiveSession } from "@/lib/api/schemas";

const sampleFeatures = {
  total_frames: 420,
  unique_can_ids: 1,
  extended_frame_count: 0,
  unique_payload_count: 1,
  max_id_share_pct: 98.5,
  id_0x100_count: 414,
  id_0x100_share_pct: 98.5,
  id_0x101_count: 0,
  id_0x101_share_pct: 0,
  id_0x102_count: 0,
  id_0x102_share_pct: 0,
  id_0x999_count: 0,
  id_0x999_share_pct: 0,
  other_id_count: 6,
};

const sampleIncident: LiveIncident = {
  incident_id: "INC-0001",
  severity: "HIGH",
  status: "OPEN",
  start_window: 4,
  end_window: 5,
  window_count: 2,
  start_time_utc: "2026-11-09T16:44:50.123456Z",
  end_time_utc: "2026-11-09T16:44:51.123456Z",
  affected_can_ids: ["0x100"],
  response_evidence: {
    can_id_counts: { "0x100": 820 },
    unexpected_can_ids: [],
    dominant_can_id: "0x100",
    dominant_can_id_share_pct: 98.5,
  },
  reasons: [
    {
      code: "HIGH_TRAFFIC_VOLUME",
      message: "High frame volume observed in this 1-second window.",
      evidence: { total_frames: 420, threshold: 100 },
    },
    {
      code: "DOMINANT_CAN_ID",
      message: "A single CAN ID dominates the window's traffic.",
      evidence: { max_id_share_pct: 98.5, threshold: 90 },
    },
  ],
  windows: [
    {
      window_index: 4,
      window_start_utc: "2026-11-09T16:44:50.123456Z",
      prediction: "ANOMALY",
      anomaly_score: 0.8412,
      features: sampleFeatures,
    },
    {
      window_index: 5,
      window_start_utc: "2026-11-09T16:44:51.123456Z",
      prediction: "ANOMALY",
      anomaly_score: 0.8521,
      features: sampleFeatures,
    },
  ],
  summary: "2 consecutive anomalous windows correlated from window 4 to 5.",
  analysis_id: "analysis_live_session123_incident_0001",
  analysis_registered: true,
  response_state: "VERIFIED",
  response_result: {
    status: "VERIFIED",
    plan: {
      incident_id: "INC-0001",
      classification: "HIGH_FREQUENCY_FLOOD",
      action: "SIMULATED_RATE_LIMIT",
      description: "Rate-limit the dominant CAN ID in offline replay.",
      target_can_ids: ["0x100"],
      status: "PLANNED",
      mode: "SIMULATION",
    },
    verification: {
      recovery: {
        verified: true,
        baseline_frame_rate: 420,
        post_mitigation_frame_rate: 20,
        remaining_unexpected_ids: 0,
      },
    },
  },
};

const sampleSession: LiveSession = {
  id: "session123",
  data_source: "backend",
  state: "capturing",
  interface: "vcan0",
  capture_file: "live_capture.csv",
  started_at: "2026-11-09T16:44:00.000000Z",
  frames_captured: 1200,
  windows: [],
  pending_window_index: 6,
  message: "Monitoring vcan0",
  incidents: [sampleIncident],
  attack: {
    state: "STOPPED",
    mode: 1,
    pid: 9876,
  },
  recovery: {
    state: "RECOVERED",
    normal_windows: 2,
    required_normal_windows: 2,
    stopped_after_window_index: 5,
  },
};

describe("SecurityAlertModal", () => {
  it("computes attack classification accurately for high frequency flood", () => {
    const classification = getAttackClassification(sampleIncident);
    expect(classification.category).toContain("Flooding");
    expect(classification.category).toContain("DoS");
  });

  it("renders modal with genuine backend incident data, severity, timestamp and score", () => {
    const onClose = vi.fn();
    const onOpenAnalysis = vi.fn();

    render(
      <SecurityAlertModal
        incident={sampleIncident}
        session={sampleSession}
        isOpen={true}
        onClose={onClose}
        onOpenAnalysis={onOpenAnalysis}
      />,
    );

    // SOC header and incident ID
    expect(screen.getByText(/SOC Security Alert/i)).toBeTruthy();
    expect(screen.getByText("INC-0001")).toBeTruthy();
    expect(screen.getByText(/Interface: vcan0/i)).toBeTruthy();

    // Severity and category
    expect(screen.getByText(/HIGH SEVERITY/i)).toBeTruthy();
    expect(screen.getByText(/CAN Bus Flooding/i)).toBeTruthy();

    // Actual detection timestamp (formatted)
    expect(screen.getByText(/16:44:50/i)).toBeTruthy();
    expect(screen.getByText(/#4 – #5 \(2s\)/i)).toBeTruthy();

    // Suspicious CAN IDs and peak score
    expect(screen.getByText("0x100")).toBeTruthy();
    expect(screen.getByText(/98.5% volume/i)).toBeTruthy();
    expect(screen.getByText("0.8521")).toBeTruthy();

    // All 5 automated response lifecycle milestones
    expect(screen.getByText(/Detection confirmed/i)).toBeTruthy();
    expect(screen.getByText(/Response initiated/i)).toBeTruthy();
    expect(screen.getByText(/Malicious simulator terminated/i)).toBeTruthy();
    expect(screen.getByText(/Recovery verification pending/i)).toBeTruthy();
    expect(screen.getByText(/Recovery verified/i)).toBeTruthy();

    // Primary action button to open complete incident details
    const openBtn = screen.getByText(/Open Full Incident Dossier \(INC-0001\)/i);
    expect(openBtn).toBeTruthy();

    fireEvent.click(openBtn);
    expect(onOpenAnalysis).toHaveBeenCalledWith("analysis_live_session123_incident_0001");
    expect(onClose).toHaveBeenCalled();
  });

  it("calls onClose when acknowledge button is clicked", () => {
    const onClose = vi.fn();
    const onOpenAnalysis = vi.fn();

    render(
      <SecurityAlertModal
        incident={sampleIncident}
        session={sampleSession}
        isOpen={true}
        onClose={onClose}
        onOpenAnalysis={onOpenAnalysis}
      />,
    );

    const ackBtn = screen.getByText(/Acknowledge & Dismiss Alert/i);
    fireEvent.click(ackBtn);
    expect(onClose).toHaveBeenCalled();
  });

  it("handles unexpected CAN ID injection attack classification", () => {
    const unexpectedIncident: LiveIncident = {
      ...sampleIncident,
      incident_id: "INC-0002",
      affected_can_ids: ["0x999"],
      response_evidence: {
        can_id_counts: { "0x999": 25 },
        unexpected_can_ids: ["0x999"],
        dominant_can_id: "0x999",
        dominant_can_id_share_pct: 100,
      },
      reasons: [
        {
          code: "UNEXPECTED_CAN_ID",
          message: "CAN traffic contains IDs outside known-ID set.",
          evidence: { other_id_count: 25 },
        },
      ],
      response_result: {
        status: "VERIFIED",
        plan: {
          incident_id: "INC-0002",
          classification: "UNEXPECTED_CAN_ID",
          action: "SIMULATED_ID_QUARANTINE",
          description: "Quarantine unexpected ID in offline replay.",
          target_can_ids: ["0x999"],
          status: "PLANNED",
          mode: "SIMULATION",
        },
      },
    };

    const classification = getAttackClassification(unexpectedIncident);
    expect(classification.category).toContain("Unauthorized CAN ID");
  });
});
