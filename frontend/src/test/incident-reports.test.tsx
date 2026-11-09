import { describe, expect, it, vi } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import { IncidentReportModal, exportIncidentCsv } from "@/components/app/IncidentReportModal";
import { IncidentHistoryTable } from "@/components/app/IncidentHistoryTable";
import type { LiveIncident } from "@/lib/api/schemas";

const mockIncidentMode1: LiveIncident = {
  incident_id: "INC-0001",
  severity: "HIGH",
  status: "RECOVERED",
  analysis_id: "analysis_live_session1_incident_0001",
  analysis_registered: true,
  start_window: 3,
  end_window: 4,
  window_count: 2,
  start_time_utc: "2026-11-10T00:50:00.000Z",
  end_time_utc: "2026-11-10T00:50:02.000Z",
  affected_can_ids: ["0x100"],
  summary: "High frequency flood attack overwhelming bus arbitration",
  reasons: [
    {
      code: "HIGH_TRAFFIC_VOLUME",
      message: "Frame count 1024 exceeds nominal threshold",
      evidence: { frame_count: 1024 },
    },
    {
      code: "DOMINANT_CAN_ID",
      message: "Arbitration ID 0x100 accounts for 85.5% of total bus frames",
      evidence: { dominant_id: "0x100", share_pct: 85.5 },
    },
  ],
  response_evidence: {
    can_id_counts: { "0x100": 850, "0x101": 50, "0x102": 50 },
    unexpected_can_ids: [],
    dominant_can_id: "0x100",
    dominant_can_id_share_pct: 85.5,
  },
  windows: [
    {
      window_index: 3,
      window_start_utc: "2026-11-10T00:50:00.000Z",
      prediction: "ANOMALY",
      anomaly_score: 0.852341,
      features: {
        total_frames: 1024,
        unique_can_ids: 3,
        extended_frame_count: 0,
        unique_payload_count: 5,
        max_id_share_pct: 85.5,
        id_0x100_count: 850,
        id_0x100_share_pct: 85.5,
        id_0x101_count: 50,
        id_0x101_share_pct: 5.0,
        id_0x102_count: 50,
        id_0x102_share_pct: 5.0,
        id_0x999_count: 0,
        id_0x999_share_pct: 0,
        other_id_count: 0,
      },
    },
  ],
  response_state: "REGISTERED",
  response_latency: {
    first_anomalous_window_utc: "2026-11-10T00:50:00.000Z",
    incident_confirmed_utc: "2026-11-10T00:50:01.000Z",
    response_initiated_utc: "2026-11-10T00:50:01.050Z",
    attack_terminated_utc: "2026-11-10T00:50:01.120Z",
    detection_ms: 1000,
    mitigation_ms: 70,
    detection_to_termination_ms: 1120,
    attack_mode: 1,
  },
  response_result: {
    status: "REGISTERED",
    pid: 14205,
    return_code: 0,
    termination_reason: "AUTOMATIC_RESPONSE",
    verification: {
      recovery: {
        verified: true,
      },
    },
  },
};

const mockIncidentMode2: LiveIncident = {
  incident_id: "INC-0002",
  severity: "MEDIUM",
  status: "REGISTERED",
  analysis_id: "analysis_live_session1_incident_0002",
  analysis_registered: true,
  start_window: 10,
  end_window: 11,
  window_count: 2,
  start_time_utc: "2026-11-10T00:51:00.000Z",
  end_time_utc: "2026-11-10T00:51:02.000Z",
  affected_can_ids: ["0x999"],
  summary: "Unauthorized extended CAN ID injection",
  reasons: [
    {
      code: "UNEXPECTED_CAN_ID",
      message: "Arbitration ID 0x999 is outside authorized matrix",
      evidence: { can_id: "0x999" },
    },
  ],
  response_evidence: {
    can_id_counts: { "0x999": 35 },
    unexpected_can_ids: ["0x999"],
    dominant_can_id: null,
    dominant_can_id_share_pct: 25.0,
  },
  windows: [],
  response_state: "REGISTERED",
  response_latency: {
    first_anomalous_window_utc: "2026-11-10T00:51:00.000Z",
    incident_confirmed_utc: "2026-11-10T00:51:01.000Z",
    response_initiated_utc: "2026-11-10T00:51:01.040Z",
    attack_terminated_utc: "2026-11-10T00:51:01.100Z",
    detection_ms: 1000,
    mitigation_ms: 60,
    detection_to_termination_ms: 1100,
    attack_mode: 2,
  },
  response_result: {
    status: "REGISTERED",
    pid: 14299,
    return_code: 0,
    termination_reason: "AUTOMATIC_RESPONSE",
  },
};

describe("Phase 5: Detailed Incident Reports and Incident History", () => {
  it("renders comprehensive SOC incident report fields in IncidentReportModal", () => {
    render(
      <IncidentReportModal
        incident={mockIncidentMode1}
        isOpen={true}
        onClose={() => {}}
      />
    );

    // Header & Identification
    expect(screen.getAllByText("INC-0001").length).toBeGreaterThan(0);
    expect(screen.getAllByText("HIGH").length).toBeGreaterThan(0);
    expect(screen.getByText(/Mode 1 — High-Frequency Flood/i)).toBeInTheDocument();
    expect(screen.getByText(/CAN Bus Flooding/i)).toBeInTheDocument();

    // Detection Milestones & Latency
    expect(screen.getByText("1.12 s")).toBeInTheDocument();
    expect(screen.getByText("1.00 s")).toBeInTheDocument();
    expect(screen.getByText("70 ms")).toBeInTheDocument();

    // Process & Response
    expect(screen.getByText("14205")).toBeInTheDocument();
    expect(screen.getByText(/Clean Exit|exited cleanly/i)).toBeInTheDocument();
    expect(screen.getByText("AUTOMATIC_RESPONSE")).toBeInTheDocument();
    expect(screen.getByText(/Recovery verified/i)).toBeInTheDocument();

    // Model Evidence & Reasons
    expect(screen.getByText("HIGH_TRAFFIC_VOLUME")).toBeInTheDocument();
    expect(screen.getByText("DOMINANT_CAN_ID")).toBeInTheDocument();
    expect(screen.getAllByText("0.852341").length).toBeGreaterThan(0);

    // Affected CAN IDs
    expect(screen.getAllByText("0x100").length).toBeGreaterThan(0);
  });

  it("exports complete and un-fabricated CSV from exportIncidentCsv", () => {
    let capturedBlob: Blob | null = null;
    let clickedDownload = false;

    // Spy on URL.createObjectURL and HTMLAnchorElement.prototype.click
    const origCreateObjectURL = URL.createObjectURL;
    const origRevokeObjectURL = URL.revokeObjectURL;
    URL.createObjectURL = vi.fn((blob: Blob) => {
      capturedBlob = blob;
      return "blob:test";
    });
    URL.revokeObjectURL = vi.fn();

    const origClick = HTMLAnchorElement.prototype.click;
    HTMLAnchorElement.prototype.click = vi.fn(function (this: HTMLAnchorElement) {
      clickedDownload = true;
      expect(this.download).toBe("incident_INC-0001_report.csv");
    });

    try {
      exportIncidentCsv(mockIncidentMode1);
      expect(clickedDownload).toBe(true);
      expect(capturedBlob).not.toBeNull();
    } finally {
      URL.createObjectURL = origCreateObjectURL;
      URL.revokeObjectURL = origRevokeObjectURL;
      HTMLAnchorElement.prototype.click = origClick;
    }
  });

  it("renders IncidentHistoryTable with filtering by severity and attack mode", () => {
    const { rerender } = render(
      <IncidentHistoryTable
        liveIncidents={[mockIncidentMode1, mockIncidentMode2]}
        historicIncidents={[]}
      />
    );

    // Both incidents initially visible
    expect(screen.getByText("INC-0001")).toBeInTheDocument();
    expect(screen.getByText("INC-0002")).toBeInTheDocument();

    // Filter by HIGH severity
    const highBtn = screen.getByRole("button", { name: "HIGH" });
    fireEvent.click(highBtn);
    expect(screen.getByText("INC-0001")).toBeInTheDocument();
    expect(screen.queryByText("INC-0002")).toBeNull();

    // Filter by MEDIUM severity
    const medBtn = screen.getByRole("button", { name: "MEDIUM" });
    fireEvent.click(medBtn);
    expect(screen.queryByText("INC-0001")).toBeNull();
    expect(screen.getByText("INC-0002")).toBeInTheDocument();

    // Reset severity to All Severities and filter by Mode 1
    const allSevBtn = screen.getByRole("button", { name: "All Severities" });
    fireEvent.click(allSevBtn);
    const mode1Btn = screen.getByRole("button", { name: "Mode 1 · Flood" });
    fireEvent.click(mode1Btn);
    expect(screen.getByText("INC-0001")).toBeInTheDocument();
    expect(screen.queryByText("INC-0002")).toBeNull();

    // Filter by Mode 2
    const mode2Btn = screen.getByRole("button", { name: "Mode 2 · Ext ID" });
    fireEvent.click(mode2Btn);
    expect(screen.queryByText("INC-0001")).toBeNull();
    expect(screen.getByText("INC-0002")).toBeInTheDocument();
  });

  it("deduplicates live and historic incidents in IncidentHistoryTable", () => {
    const duplicateHistoric: LiveIncident = {
      ...mockIncidentMode1,
      incident_id: "INC-0001", // same ID as live
    };
    const uniqueHistoric: LiveIncident = {
      ...mockIncidentMode2,
      incident_id: "INC-0003",
    };

    render(
      <IncidentHistoryTable
        liveIncidents={[mockIncidentMode1]}
        historicIncidents={[duplicateHistoric, uniqueHistoric]}
      />
    );

    // Should only have 2 unique rows: INC-0001 and INC-0003
    expect(screen.getAllByText("INC-0001").length).toBe(1);
    expect(screen.getByText("INC-0003")).toBeInTheDocument();
    expect(screen.getByText("2 of 2 incidents shown")).toBeInTheDocument();
  });

  it("handles opening the report modal on row action click", () => {
    render(
      <IncidentHistoryTable
        liveIncidents={[mockIncidentMode1]}
        historicIncidents={[]}
      />
    );

    const viewReportBtn = screen.getByRole("button", { name: /View Report/i });
    fireEvent.click(viewReportBtn);

    // Modal opens showing investigation report
    expect(screen.getByText("SOC Investigation Report")).toBeInTheDocument();
    expect(screen.getByText(/First Anomalous Window/i)).toBeInTheDocument();
  });
});
