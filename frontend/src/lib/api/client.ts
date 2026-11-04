// The single seam between the UI and the CAN-Sentinel backend.
import type {
  AnalysisResult,
  AnalysisSummary,
  CapturePreset,
  LiveSession,
  SystemStatus,
} from "./schemas";

export type BackendMode = "demo" | "api";

export interface ApiClient {
  readonly mode: BackendMode;
  getStatus(): Promise<SystemStatus>;
  listPresets(): Promise<CapturePreset[]>;
  listAnalyses(): Promise<AnalysisSummary[]>;
  getAnalysis(id: string): Promise<AnalysisResult>;
  /** Analyse a capture file that already exists on the backend host. */
  analyzeCapture(input: { capture_path: string; origin?: "preset" | "path" }): Promise<AnalysisResult>;
  /** Upload a sniffer CSV for the backend to validate and score. */
  uploadCapture(file: File): Promise<AnalysisResult>;
  /** Report CSV (reports/<capture>_inference.csv). */
  getReportCsv(id: string): Promise<{ filename: string; csv: string }>;
  startLiveCapture(): Promise<LiveSession>;
  getLiveSession(id: string): Promise<LiveSession>;
  /** Stop capture and run final inference ("Stop & Analyze"). */
  stopLiveCapture(id: string): Promise<AnalysisResult>;
}

export class ApiError extends Error {
  constructor(
    message: string,
    readonly status?: number,
    readonly kind: "network" | "http" | "contract" = "http",
  ) {
    super(message);
    this.name = "ApiError";
  }
}
