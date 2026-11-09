// Data models shared with the Python backend (future FastAPI service).
// Field names mirror the backend's CSV/report columns (score_capture.py,
// frequency_analyzer.py) so the API can serialise them without renaming.
import { z } from "zod";

export const FEATURE_COLUMNS = [
  "total_frames",
  "unique_can_ids",
  "extended_frame_count",
  "unique_payload_count",
  "max_id_share_pct",
  "id_0x100_count",
  "id_0x100_share_pct",
  "id_0x101_count",
  "id_0x101_share_pct",
  "id_0x102_count",
  "id_0x102_share_pct",
  "id_0x999_count",
  "id_0x999_share_pct",
  "other_id_count",
] as const;

export type FeatureColumn = (typeof FEATURE_COLUMNS)[number];

export const DataSource = z.enum(["demo", "backend"]);
export type DataSource = z.infer<typeof DataSource>;

export const Prediction = z.enum(["NORMAL", "ANOMALY"]);
export type Prediction = z.infer<typeof Prediction>;

export const WindowFeatures = z.object(
  Object.fromEntries(FEATURE_COLUMNS.map((c) => [c, z.number()])) as Record<FeatureColumn, z.ZodNumber>,
);
export type WindowFeatures = z.infer<typeof WindowFeatures>;

/** Evidence-based explanation attached to an anomalous window. */
export const AlertReason = z.object({
  code: z.string(),
  message: z.string(),
  evidence: z.record(z.string(), z.unknown()),
});

export const AlertExplanation = z.object({
  reasons: z.array(AlertReason),
  severity: z.enum(["INFO", "MEDIUM", "HIGH", "REVIEW"]),
  summary: z.string(),
});

export type AlertReason = z.infer<typeof AlertReason>;
export type AlertExplanation = z.infer<typeof AlertExplanation>;

/** One scored 1-second window (a row of reports/<capture>_inference.csv). */
export const ResponseEvidence = z.object({
  can_id_counts: z.record(z.string(), z.number().int()),
  unexpected_can_ids: z.array(z.string()),
  dominant_can_id: z.string().nullable(),
  dominant_can_id_share_pct: z.number(),
});

export const InferenceWindow = z.object({
  window_index: z.number().int(),
  window_start_utc: z.string(),
  prediction: Prediction,
  anomaly_score: z.number(),
  features: WindowFeatures,
  explanation: AlertExplanation.optional(),
  response_evidence: ResponseEvidence.optional(),
});
export type InferenceWindow = z.infer<typeof InferenceWindow>;
/** A group of correlated anomalous CAN windows. */
export const Incident = z.object({
  incident_id: z.string(),
  severity: z.enum(["HIGH", "MEDIUM", "REVIEW"]),
  status: z.string(),
  start_window: z.number().int(),
  end_window: z.number().int(),
  window_count: z.number().int(),
  start_time_utc: z.string(),
  end_time_utc: z.string(),
  affected_can_ids: z.array(z.string()),
  response_evidence: ResponseEvidence.optional(),
  reasons: z.array(AlertReason),
  windows: z.array(InferenceWindow),
  summary: z.string(),
});

export type Incident = z.infer<typeof Incident>;

export const ResponsePlan = z.object({
  incident_id: z.string(),
  classification: z.string(),
  action: z.enum([
    "SIMULATED_RATE_LIMIT",
    "SIMULATED_ID_QUARANTINE",
    "MANUAL_REVIEW",
  ]),
  description: z.string(),
  target_can_ids: z.array(z.string()),
  status: z.string(),
  mode: z.literal("SIMULATION"),
});

export type ResponsePlan = z.infer<typeof ResponsePlan>;

export const ReplayResult = z.object({
  mode: z.literal("OFFLINE_SIMULATION"),
  action: z.string(),
  before: z.object({
    total_frames: z.number(),
    frames_by_can_id: z.record(z.string(), z.number()),
    unique_can_ids: z.number(),
  }),
  after: z.object({
    total_frames: z.number(),
    frames_by_can_id: z.record(z.string(), z.number()),
    unique_can_ids: z.number(),
  }),
  removed_frames: z.number(),
  removed_can_ids: z.record(z.string(), z.number()),
  original_preserved: z.boolean(),
});

export type ReplayResult = z.infer<typeof ReplayResult>;

export const ResponseActivation = z.object({
  incident_id: z.string(),
  classification: z.string(),
  action: z.string(),
  description: z.string(),
  target_can_ids: z.array(z.string()),
  status: z.string(),
  mode: z.literal("SIMULATION"),
  replay_result: ReplayResult.optional(),
});

export type ResponseActivation = z.infer<typeof ResponseActivation>;
export const RecoveryVerification = ResponseActivation.extend({
  recovery: z.object({
    verified: z.boolean(),
    baseline_frame_rate: z.number(),
    post_mitigation_frame_rate: z.number(),
    remaining_unexpected_ids: z.number().int(),
  }),
});

export type RecoveryVerification = z.infer<typeof RecoveryVerification>;
/** Per-ID row from frequency_analyzer.build_frequency_summary. */
export const FrequencyRow = z.object({
  can_id: z.string(),
  frame_format: z.string(),
  frame_count: z.number(),
  percentage_of_total: z.number(),
  unique_payload_count: z.number(),
  mean_interarrival_ms: z.number().nullable(),
  median_interarrival_ms: z.number().nullable(),
  min_interarrival_ms: z.number().nullable(),
  max_interarrival_ms: z.number().nullable(),
});
export type FrequencyRow = z.infer<typeof FrequencyRow>;

export const ModelInfo = z.object({
  loaded: z.boolean(),
  path: z.string(),
  algorithm: z.string(),
  contamination: z.number().nullable(),
  training_windows: z.number().nullable(),
  window_ms: z.number(),
  feature_columns: z.array(z.string()),
  sklearn_version: z.string().nullable(),
});
export type ModelInfo = z.infer<typeof ModelInfo>;

export const SystemStatus = z.object({
  data_source: DataSource,
  backend_version: z.string(),
  interface: z.object({
    name: z.string(),
    state: z.enum(["UP", "DOWN", "MISSING", "UNKNOWN"]),
  }),
  sniffer: z.object({ built: z.boolean(), path: z.string() }),
  model: ModelInfo,
  checked_at: z.string(),
});
export type SystemStatus = z.infer<typeof SystemStatus>;

export const CapturePreset = z.object({
  id: z.string(),
  label: z.string(),
  path: z.string(),
  available: z.boolean(),
});
export type CapturePreset = z.infer<typeof CapturePreset>;

export const AnalysisOrigin = z.enum(["preset", "path", "upload", "live"]);

export const AnalysisSummary = z.object({
  id: z.string(),
  data_source: DataSource,
  capture_file: z.string(),
  origin: AnalysisOrigin,
  created_at: z.string(),
  frames_loaded: z.number(),
  windows_scored: z.number(),
  normal_count: z.number(),
  anomaly_count: z.number(),
});
export type AnalysisSummary = z.infer<typeof AnalysisSummary>;

export const AnalysisResult = AnalysisSummary.extend({
  /** Index of the possibly-incomplete final window the backend excluded. */
  excluded_partial_window: z.number().nullable(),
  model: ModelInfo,
  windows: z.array(InferenceWindow),
  incidents: z.array(Incident).optional(),
  frequency_summary: z.array(FrequencyRow),
  notes: z.array(z.string()),
});
export type AnalysisResult = z.infer<typeof AnalysisResult>;

export const LiveState = z.enum(["capturing", "stopping", "stopped", "error"]);
export type LiveState = z.infer<typeof LiveState>;

export const LiveAttack = z.object({
  state: z.string(),
  mode: z.number().optional(),
  pid: z.number().optional(),
  return_code: z.number().nullable().optional(),
});
export const LiveRecovery = z.object({
  state: z.string(),
  normal_windows: z.number().optional(),
  required_normal_windows: z.number().optional(),
  stopped_after_window_index: z.number().nullable().optional(),
});
export const LiveAttackResult = z.object({
  mode: z.number(),
  pid: z.number(),
  state: z.string(),
});
export type LiveAttackResult = z.infer<typeof LiveAttackResult>;

export const LiveIncident = Incident.passthrough().extend({
  analysis_id: z.string().optional(),
  analysis_registered: z.boolean().optional(),
  response_state: z.string().optional(),
  response_result: z.record(z.string(), z.unknown()).optional(),
});
export type LiveIncident = z.infer<typeof LiveIncident>;

export const LiveSession = z.object({
  id: z.string(),
  data_source: DataSource,
  state: LiveState,
  interface: z.string(),
  capture_file: z.string(),
  started_at: z.string(),
  frames_captured: z.number(),
  /** Completed windows scored incrementally by the saved model. */
  windows: z.array(InferenceWindow),
  /** Newest, possibly incomplete window that is not scored yet. */
  pending_window_index: z.number().nullable(),
  message: z.string().nullable(),
  incidents: z.array(LiveIncident).optional(),
  attack: LiveAttack.optional(),
  recovery: LiveRecovery.optional(),
});
export type LiveSession = z.infer<typeof LiveSession>;

export const ApiErrorBody = z.object({ detail: z.union([z.string(), z.array(z.unknown())]) });
