import { describe, expect, it } from "vitest";

import {
  analyzeDoneMessage,
  analyzeErrorMessage,
  analyzeStartMessage,
  liveAnomalyMessage,
  liveStartMessage,
  liveStopMessage,
  uploadStartMessage,
} from "@/lib/audit-messages";
import { FEATURE_COLUMNS, type AnalysisResult, type InferenceWindow, type WindowFeatures } from "@/lib/api/schemas";

const FEATURES = Object.fromEntries(FEATURE_COLUMNS.map((c) => [c, 0])) as WindowFeatures;

const scoredWindow = (over: Partial<WindowFeatures> = {}): InferenceWindow => ({
  window_index: 4,
  window_start_utc: "2026-10-24T08:00:04.000000Z",
  prediction: "ANOMALY",
  anomaly_score: 0.8234,
  features: { ...FEATURES, ...over },
});

const analysis = (over: Partial<AnalysisResult> = {}): AnalysisResult => ({
  id: "demo-1",
  data_source: "demo",
  capture_file: "high_frequency_capture.csv",
  origin: "preset",
  created_at: "2026-10-24T08:01:00.000Z",
  frames_loaded: 17700,
  windows_scored: 43,
  normal_count: 0,
  anomaly_count: 43,
  excluded_partial_window: null,
  model: {
    loaded: true,
    path: "models/isolation_forest_baseline.joblib",
    algorithm: "IsolationForest (n_estimators=200, random_state=42)",
    contamination: 0.02,
    training_windows: 47,
    window_ms: 1000,
    feature_columns: [...FEATURE_COLUMNS],
    sklearn_version: null,
  },
  windows: [],
  frequency_summary: [],
  notes: [],
  ...over,
});

/** Claims only the real Python backend is entitled to make. */
const BACKEND_ONLY = [
  "Running saved-model inference",
  "Analysis complete",
  "Capture stored",
  "Live capture started",
  "classified ANOMALY",
  "Uploading",
];

describe("Audit log messages", () => {
  it("never lets a demo entry claim a real backend operation", () => {
    const demoEntries = [
      analyzeStartMessage(true, "data/high_frequency_capture.csv"),
      uploadStartMessage(true, "my_capture.csv"),
      analyzeDoneMessage(true, analysis()),
      analyzeErrorMessage(true, "Capture must be a .csv file"),
      liveStartMessage(true, "vcan0", "dashboard_capture_2026.csv"),
      liveAnomalyMessage(true, scoredWindow({ total_frames: 412 })),
      liveStopMessage(true, analysis()),
    ];
    for (const entry of demoEntries) {
      for (const claim of BACKEND_ONLY) {
        expect(entry).not.toContain(claim);
      }
    }
  });

  it("labels every demo stage with wording that says the data is illustrative", () => {
    expect(analyzeStartMessage(true, "data/x.csv")).toContain("Starting illustrative demo analysis");
    expect(uploadStartMessage(true, "x.csv")).toContain("Starting illustrative demo analysis");
    expect(analyzeDoneMessage(true, analysis())).toContain("Demo analysis completed — scripted results");
    expect(liveStartMessage(true, "vcan0", "x.csv")).toContain("Demo capture session started — simulated vcan0 traffic");
    expect(liveAnomalyMessage(true, scoredWindow())).toContain("Demo anomaly event — illustrative prediction");
    expect(liveStopMessage(true, analysis())).toContain("Demo capture session ended — scripted results");
  });

  it("keeps real-backend wording exactly as before", () => {
    expect(analyzeStartMessage(false, "data/x.csv")).toBe("Running saved-model inference on data/x.csv");
    expect(uploadStartMessage(false, "x.csv")).toBe("Uploading x.csv for inference");
    expect(analyzeDoneMessage(false, analysis())).toBe(
      "Analysis complete: high_frequency_capture.csv — 43/43 windows anomalous",
    );
    expect(analyzeErrorMessage(false, "boom")).toBe("Analysis error: boom");
    expect(liveStartMessage(false, "vcan0", "cap.csv")).toBe("Live capture started on vcan0 → cap.csv");
    expect(liveAnomalyMessage(false, scoredWindow({ total_frames: 412 }))).toBe(
      "Window #4 classified ANOMALY — score 0.8234, 412 frames",
    );
    expect(liveStopMessage(false, analysis())).toBe("Capture stored: high_frequency_capture.csv. Final inference: 43/43 anomalous");
  });

  it("shows the reader the same scripted numbers the screen displays", () => {
    expect(analyzeDoneMessage(true, analysis())).toContain("43/43");
    expect(liveStopMessage(true, analysis())).toContain("43/43");
    expect(liveAnomalyMessage(true, scoredWindow({ total_frames: 412 }))).toContain("412 simulated frames");
    expect(liveAnomalyMessage(true, scoredWindow({ total_frames: 412 }))).toContain("0.8234");
  });

  it("keeps demo and backend wording distinct for the same event", () => {
    const pairs: [string, string][] = [
      [analyzeStartMessage(true, "data/x.csv"), analyzeStartMessage(false, "data/x.csv")],
      [uploadStartMessage(true, "x.csv"), uploadStartMessage(false, "x.csv")],
      [analyzeDoneMessage(true, analysis()), analyzeDoneMessage(false, analysis())],
      [analyzeErrorMessage(true, "boom"), analyzeErrorMessage(false, "boom")],
      [liveStartMessage(true, "vcan0", "cap.csv"), liveStartMessage(false, "vcan0", "cap.csv")],
      [liveAnomalyMessage(true, scoredWindow()), liveAnomalyMessage(false, scoredWindow())],
      [liveStopMessage(true, analysis()), liveStopMessage(false, analysis())],
    ];
    for (const [demoMsg, backendMsg] of pairs) {
      expect(demoMsg).not.toBe(backendMsg);
    }
  });
});
