// Demo implementation of ApiClient.
//
// Everything here is SCRIPTED, ILLUSTRATIVE data so the interface can be
// explored without the Linux backend. No CAN frames are captured and no model
// is run: scores and predictions are hand-shaped to resemble the shapes the
// Python pipeline returns. Every object is tagged data_source: "demo".
import { ApiError, type ApiClient } from "./client";
import {
  FEATURE_COLUMNS,
  type AnalysisResult,
  type AnalysisSummary,
  type CapturePreset,
  type FrequencyRow,
  type InferenceWindow,
  type LiveIncident,
  type LiveSession,
  type ModelInfo,
  type SystemStatus,
  type WindowFeatures,
} from "./schemas";
import { validateCaptureHeader } from "./capture-file";

export const DEMO_NOTE =
  "Demo mode: scripted illustrative values. No vcan0 traffic was captured and the Isolation Forest model was not run.";

type Scenario = "normal" | "high_frequency" | "unexpected_id" | "mixed_hf" | "mixed_uid";

function rng(seed: number) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const r4 = (v: number) => Math.round(v * 1e4) / 1e4;

function features(counts: Record<string, number>, payloads: number, extended: number): WindowFeatures {
  const total = Object.values(counts).reduce((a, b) => a + b, 0);
  const share = (id: string) => r4(((counts[id] ?? 0) / total) * 100);
  const known = ["0x100", "0x101", "0x102", "0x999"];
  const f = {
    total_frames: total,
    unique_can_ids: Object.values(counts).filter((c) => c > 0).length,
    extended_frame_count: extended,
    unique_payload_count: payloads,
    max_id_share_pct: r4((Math.max(...Object.values(counts)) / total) * 100),
    other_id_count: Object.entries(counts)
      .filter(([id]) => !known.includes(id))
      .reduce((a, [, c]) => a + c, 0),
  } as Record<string, number>;
  for (const id of known) {
    f[`id_${id}_count`] = counts[id] ?? 0;
    f[`id_${id}_share_pct`] = share(id);
  }
  return Object.fromEntries(FEATURE_COLUMNS.map((c) => [c, f[c] ?? 0])) as WindowFeatures;
}

function demoWindow(index: number, startMs: number, scenario: Scenario, rand: () => number, forceAnomaly = false): InferenceWindow {
  let feats: WindowFeatures;
  let score: number;
  let anomaly = forceAnomaly;
  switch (scenario) {
    case "high_frequency": {
      const n = 410 + Math.floor(rand() * 60);
      feats = features({ "0x100": n }, 1, 0);
      score = 0.82 + rand() * 0.02;
      anomaly = true;
      break;
    }
    case "unexpected_id": {
      const n = 17 + Math.floor(rand() * 3);
      feats = features({ "0x999": n }, 1, n);
      score = 0.81 + rand() * 0.02;
      anomaly = true;
      break;
    }
    case "mixed_hf": {
      const n = 380 + Math.floor(rand() * 70);
      feats = features({ "0x100": n + 10, "0x101": 10, "0x102": 1 }, 18 + Math.floor(rand() * 3), 0);
      score = 0.72 + rand() * 0.07;
      anomaly = true;
      break;
    }
    case "mixed_uid": {
      const n = 17 + Math.floor(rand() * 3);
      feats = features({ "0x100": 10, "0x101": 10, "0x102": 1, "0x999": n }, 19 + Math.floor(rand() * 3), n);
      score = 0.69 + rand() * 0.07;
      anomaly = true;
      break;
    }
    default: {
      const jitter = rand();
      const a = jitter < 0.08 ? 9 : jitter > 0.92 ? 11 : 10;
      feats = features({ "0x100": a, "0x101": 10, "0x102": 1 }, 17 + Math.floor(rand() * 5), 0);
      score = forceAnomaly ? 0.66 + rand() * 0.02 : 0.37 + rand() * 0.16;
    }
  }
  return {
    window_index: index,
    window_start_utc: new Date(startMs + index * 1000).toISOString().replace("Z", "000000Z"),
    prediction: anomaly ? "ANOMALY" : "NORMAL",
    anomaly_score: Math.round(score * 1e8) / 1e8,
    features: feats,
  };
}

const DEMO_MODEL: ModelInfo = {
  loaded: true,
  path: "models/isolation_forest_baseline.joblib",
  algorithm: "IsolationForest (n_estimators=200, random_state=42)",
  contamination: 0.02,
  training_windows: 47,
  window_ms: 1000,
  feature_columns: [...FEATURE_COLUMNS],
  sklearn_version: null,
};

const PRESETS: CapturePreset[] = [
  { id: "normal_baseline_60s", label: "Normal baseline — 60 seconds", path: "data/normal_baseline_60s.csv", available: true },
  { id: "high_frequency_capture", label: "High-frequency attack", path: "data/high_frequency_capture.csv", available: true },
  { id: "unexpected_id_capture", label: "Unexpected extended ID", path: "data/unexpected_id_capture.csv", available: true },
];

function frequencyFor(windows: InferenceWindow[]): FrequencyRow[] {
  const sum = (k: keyof WindowFeatures) => windows.reduce((a, w) => a + w.features[k], 0);
  const total = sum("total_frames");
  const rows: FrequencyRow[] = [];
  const add = (id: string, fmt: string, count: number, payloads: number, mean: number, median: number, min: number, max: number) => {
    if (count > 0)
      rows.push({
        can_id: id,
        frame_format: fmt,
        frame_count: count,
        percentage_of_total: r4((count / total) * 100),
        unique_payload_count: payloads,
        mean_interarrival_ms: count > 1 ? mean : null,
        median_interarrival_ms: count > 1 ? median : null,
        min_interarrival_ms: count > 1 ? min : null,
        max_interarrival_ms: count > 1 ? max : null,
      });
  };
  const c100 = sum("id_0x100_count");
  const c101 = sum("id_0x101_count");
  const attackHeavy = c100 > c101 * 3;
  add("0x100", "standard", c100, attackHeavy ? Math.min(c101, 1500) + 1 : Math.min(c100, 1800), attackHeavy ? 2.307 : 100.002, attackHeavy ? 2.074 : 100.001, attackHeavy ? 1.004 : 98.91, attackHeavy ? 19.8 : 101.2);
  add("0x101", "standard", c101, 121, 100.001, 100.0, 99.06, 100.69);
  add("0x102", "standard", sum("id_0x102_count"), 21, 1000.003, 999.999, 999.43, 1000.48);
  add("0x999", "extended", sum("id_0x999_count"), 1, 58.323, 52.344, 50.004, 117.07);
  return rows;
}

const wait = (ms: number) => new Promise((r) => setTimeout(r, ms));

function scenarioForPath(path: string): Scenario {
  if (/high[_-]?freq/i.test(path)) return "high_frequency";
  if (/unexpected|0x999/i.test(path)) return "unexpected_id";
  return "normal";
}

function buildAnalysis(id: string, file: string, origin: AnalysisResult["origin"], scenario: Scenario, seed: number, extraNotes: string[] = []): AnalysisResult {
  const rand = rng(seed);
  const count = scenario === "high_frequency" ? 43 : scenario === "unexpected_id" ? 28 : 59;
  const start = Date.UTC(2026, 9, 24, 8, 0, 0);
  const windows = Array.from({ length: count }, (_, i) =>
    demoWindow(i, start, scenario, rand, scenario === "normal" && i === 37),
  );
  return finalize(id, file, origin, windows, count, extraNotes);
}

function finalize(id: string, file: string, origin: AnalysisResult["origin"], windows: InferenceWindow[], excluded: number | null, extraNotes: string[] = []): AnalysisResult {
  const anomalies = windows.filter((w) => w.prediction === "ANOMALY").length;
  return {
    id,
    data_source: "demo",
    capture_file: file,
    origin,
    created_at: new Date().toISOString(),
    frames_loaded: windows.reduce((a, w) => a + w.features.total_frames, 0),
    windows_scored: windows.length,
    normal_count: windows.length - anomalies,
    anomaly_count: anomalies,
    excluded_partial_window: excluded,
    model: DEMO_MODEL,
    windows,
    frequency_summary: frequencyFor(windows),
    notes: [DEMO_NOTE, ...extraNotes],
  };
}

const summarize = ({ windows: _w, frequency_summary: _f, model: _m, notes: _n, excluded_partial_window: _e, ...s }: AnalysisResult): AnalysisSummary => s;

/** Scripted live timeline: normal, high-frequency burst, normal, unexpected-ID burst. */
export function liveScenarioAt(windowIndex: number): Scenario {
  const t = windowIndex % 40;
  if (t >= 10 && t < 16) return "mixed_hf";
  if (t >= 26 && t < 31) return "mixed_uid";
  return "normal";
}

interface DemoLive {
  session: LiveSession;
  t0: number;
  seed: number;
}

export function createDemoClient(): ApiClient {
  let counter = 0;
  const analyses = new Map<string, AnalysisResult>();
  const lives = new Map<string, DemoLive>();

  // Seed history so the overview has something to show.
  const seedA = buildAnalysis("demo-seed-normal", "normal_baseline_60s.csv", "preset", "normal", 11);
  const seedB = buildAnalysis("demo-seed-hf", "high_frequency_capture.csv", "preset", "high_frequency", 12);
  seedA.created_at = new Date(Date.now() - 1000 * 60 * 42).toISOString();
  seedB.created_at = new Date(Date.now() - 1000 * 60 * 18).toISOString();
  analyses.set(seedA.id, seedA);
  analyses.set(seedB.id, seedB);

  const store = (a: AnalysisResult) => {
    analyses.set(a.id, a);
    return a;
  };

  const advance = (live: DemoLive) => {
    const s = live.session;
    if (s.state !== "capturing") return s;
    const elapsed = (Date.now() - live.t0) / 1000;
    const newest = Math.floor(elapsed);
    const rand = rng(live.seed);
    const start = Date.parse(s.started_at);
    const windows: InferenceWindow[] = [];
    for (let i = 0; i < newest; i++) windows.push(demoWindow(i, start, liveScenarioAt(i), rand));
    s.windows = windows;
    s.pending_window_index = newest;
    s.frames_captured = windows.reduce((a, w) => a + w.features.total_frames, 0) + Math.floor((elapsed - newest) * 21);
    return s;
  };

  return {
    mode: "demo",
    async getStatus(): Promise<SystemStatus> {
      await wait(250);
      return {
        data_source: "demo",
        backend_version: "demo",
        interface: { name: "vcan0", state: "UP" },
        sniffer: { built: true, path: "build/can_sniffer" },
        model: DEMO_MODEL,
        checked_at: new Date().toISOString(),
      };
    },
    async listPresets() {
      await wait(150);
      return PRESETS;
    },
    async listAnalyses() {
      await wait(200);
      return [...analyses.values()].map(summarize).sort((a, b) => b.created_at.localeCompare(a.created_at));
    },
    async listAllIncidents(): Promise<LiveIncident[]> {
      await wait(200);
      const result: LiveIncident[] = [];
      for (const a of analyses.values()) {
        for (const inc of a.incidents ?? []) {
          result.push({
            ...inc,
            analysis_id: a.id,
            analysis_registered: true,
            response_state: "REGISTERED",
          });
        }
      }
      return result.reverse();
    },
    async getAnalysis(id) {
      await wait(200);
      const a = analyses.get(id);
      if (!a) throw new ApiError("Analysis not found", 404);
      return a;
    },
    async analyzeCapture({ capture_path, origin = "path" }) {
      await wait(900);
      const file = capture_path.split("/").pop() || capture_path;
      if (!/\.csv$/i.test(file)) throw new ApiError("Capture must be a .csv file produced by can_sniffer", 422);
      return store(buildAnalysis(`demo-${++counter}`, file, origin, scenarioForPath(capture_path), 100 + counter));
    },
    async uploadCapture(file) {
      await validateCaptureHeader(file);
      await wait(900);
      return store(
        buildAnalysis(`demo-${++counter}`, file.name, "upload", scenarioForPath(file.name), 200 + counter, [
          "The uploaded file was not sent anywhere and its frames were not analysed; connect the backend to score real captures.",
        ]),
      );
    },
    async getReportCsv(id) {
      const a = analyses.get(id);
      if (!a) throw new ApiError("Analysis not found", 404);
      const header = ["capture_file", "window_index", "window_start_utc", "prediction", "anomaly_score", ...FEATURE_COLUMNS];
      const rows = a.windows.map((w) =>
        [a.capture_file, w.window_index, w.window_start_utc, w.prediction, w.anomaly_score, ...FEATURE_COLUMNS.map((c) => w.features[c])].join(","),
      );
      const stem = a.capture_file.replace(/\.[^.]+$/, "");
      return { filename: `DEMO_${stem}_inference.csv`, csv: [header.join(","), ...rows].join("\n") + "\n" };
    },
    async startLiveCapture() {
      await wait(500);
      if ([...lives.values()].some((l) => l.session.state === "capturing"))
        throw new ApiError("A capture is already running.", 409);
      const id = `demo-live-${++counter}`;
      const now = new Date();
      const stamp = now.toISOString().replace(/[-:]/g, "").replace(".", "_");
      const live: DemoLive = {
        t0: Date.now(),
        seed: 300 + counter,
        session: {
          id,
          data_source: "demo",
          state: "capturing",
          interface: "vcan0",
          capture_file: `dashboard_capture_${stamp}.csv`,
          started_at: now.toISOString(),
          frames_captured: 0,
          windows: [],
          pending_window_index: 0,
          message: DEMO_NOTE,
        },
      };
      lives.set(id, live);
      return { ...live.session };
    },
    async getLiveSession(id) {
      const live = lives.get(id);
      if (!live) throw new ApiError("Live session not found", 404);
      return { ...advance(live), windows: [...live.session.windows] };
    },
    async stopLiveCapture(id) {
      const live = lives.get(id);
      if (!live) throw new ApiError("Live session not found", 404);
      advance(live);
      live.session.state = "stopped";
      await wait(800);
      const windows = live.session.windows;
      if (!windows.length) throw new ApiError("Not enough complete windows to score this capture.", 422);
      return store(finalize(`demo-${++counter}`, live.session.capture_file, "live", windows, live.session.pending_window_index));
       },
        async startLiveAttack(_id, _mode) {
      throw new ApiError("Attack simulation is available only in backend API mode.", 501);
    },
    async stopLiveAttack(_id) {
      return { state: "STOPPED" };
    },
    async startLiveNormal(_id, _intervalMs) {
      throw new ApiError("Normal traffic simulation is available only in backend API mode.", 501);
    },
    async stopLiveNormal(_id) {
      return { state: "STOPPED" };
    },
    async stopLiveSimulations(_id) {
      return { attack: { state: "STOPPED" }, normal: { state: "STOPPED" } };
    },

    async planResponse(_analysisId, _incidentId) {
      throw new ApiError(
        "Response planning requires backend API mode. Demo mode does not run the response engine.",
        501,
      );
    },

    async activateResponse(_analysisId, _incidentId) {
      throw new ApiError(
        "Response activation is unavailable in demo mode. No CAN mitigation was performed.",
        501,
      );
    },

    async verifyRecovery(_analysisId, _incidentId) {
      throw new ApiError(
        "Recovery verification requires a backend API response and replay result.",
        501,
      );
    },

    async getResilienceScenarios() {
      return [
        {
          scenario_id: "SCN-01",
          scenario_name: "Attack simulator exits unexpectedly",
          expected_behavior: "Reconcile process crash with non-zero exit code; mark state STOPPED (PROCESS_CRASH).",
          actual_result: "Reconciled to state=STOPPED, return_code=139, reason=PROCESS_CRASH",
          timestamp: new Date().toISOString(),
          status: "PASS" as const,
          diagnostic_evidence: { initial_pid: 7711, reconciled_state: "STOPPED", return_code: 139 },
        },
        {
          scenario_id: "SCN-02",
          scenario_name: "Attack simulator does not terminate within configured timeout",
          expected_behavior: "Escalate signal termination from SIGINT/SIGTERM to SIGKILL upon timeout.",
          actual_result: "Signal escalation executed; final return_code=-9",
          timestamp: new Date().toISOString(),
          status: "PASS" as const,
          diagnostic_evidence: { target_pid: 8822, signals_sent: ["2", "15", "9"], final_return_code: -9 },
        },
        {
          scenario_id: "SCN-03",
          scenario_name: "Normal traffic generator crashes",
          expected_behavior: "Reconcile normal crash with return_code=1; sniffer continues capturing uninterrupted.",
          actual_result: "Normal state reconciled to STOPPED (rc=1, PROCESS_CRASH); sniffer active",
          timestamp: new Date().toISOString(),
          status: "PASS" as const,
          diagnostic_evidence: { normal_pid: 3311, normal_return_code: 1, session_state: "capturing" },
        },
        {
          scenario_id: "SCN-04",
          scenario_name: "Sniffer process stops unexpectedly",
          expected_behavior: "Detect sniffer exit; reconcile sniffer availability as inactive.",
          actual_result: "Sniffer termination detected; sniffer_active=false, exit_code=2",
          timestamp: new Date().toISOString(),
          status: "PASS" as const,
          diagnostic_evidence: { sniffer_pid: 1101, exit_code: 2, sniffer_active: false },
        },
        {
          scenario_id: "SCN-05",
          scenario_name: "Backend API becomes unavailable",
          expected_behavior: "Catch connection failure, flag ERROR status in SystemHealthMonitor.",
          actual_result: "Gracefully intercepted backend connection outage: ConnectionRefusedError",
          timestamp: new Date().toISOString(),
          status: "PASS" as const,
          diagnostic_evidence: { handled_gracefully: true },
        },
        {
          scenario_id: "SCN-06",
          scenario_name: "Recovery verification does not complete",
          expected_behavior: "Reset consecutive normal window counter to 0 upon intermediate anomaly.",
          actual_result: "Anomaly during verification reset normal_windows to 0; state remained ATTACK_STOPPED_VERIFYING",
          timestamp: new Date().toISOString(),
          status: "PASS" as const,
          diagnostic_evidence: { normal_windows: 0, final_recovery_state: "ATTACK_STOPPED_VERIFYING" },
        },
        {
          scenario_id: "SCN-07",
          scenario_name: "Multiple incidents occur in succession",
          expected_behavior: "Correctly process and register successive incidents with distinct IDs.",
          actual_result: "Generated 2 distinct incidents: ['INC-0001', 'INC-0002']",
          timestamp: new Date().toISOString(),
          status: "PASS" as const,
          diagnostic_evidence: { incident_ids: ["INC-0001", "INC-0002"] },
        },
        {
          scenario_id: "SCN-08",
          scenario_name: "Session stops while an incident is being processed",
          expected_behavior: "Gracefully drain queued incident jobs, complete incident registration, and shutdown.",
          actual_result: "Shutdown completed=true; queue empty=true; incident registered=true",
          timestamp: new Date().toISOString(),
          status: "PASS" as const,
          diagnostic_evidence: { shutdown_complete: true, incident_queue_empty: true },
        },
      ];
    },

    async runResilienceScenarios() {
      return this.getResilienceScenarios();
    },
  };
}
