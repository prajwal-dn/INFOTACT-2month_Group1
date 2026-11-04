// Audit-log wording, split by data source.
//
// Demo mode captures no CAN frames and never runs the Isolation Forest, so its
// entries must never read like backend operations. Real-backend wording is
// unchanged: it describes what the Python service actually did.
import type { AnalysisResult, InferenceWindow } from "@/lib/api/schemas";

/** Inference on a capture that already exists on the backend host. */
export function analyzeStartMessage(demo: boolean, capturePath: string): string {
  return demo
    ? `Starting illustrative demo analysis — ${capturePath} is not read from disk; the result is scripted`
    : `Running saved-model inference on ${capturePath}`;
}

/** Uploading a sniffer CSV. */
export function uploadStartMessage(demo: boolean, fileName: string): string {
  return demo
    ? `Starting illustrative demo analysis of ${fileName} — nothing is uploaded and the file is not analysed`
    : `Uploading ${fileName} for inference`;
}

/** A finished analysis (preset, backend path, upload or live capture). */
export function analyzeDoneMessage(demo: boolean, a: AnalysisResult): string {
  return demo
    ? `Demo analysis completed — scripted results · ${a.anomaly_count}/${a.windows_scored} windows marked anomalous · no file read`
    : `Analysis complete: ${a.capture_file} — ${a.anomaly_count}/${a.windows_scored} windows anomalous`;
}

/** A failed analysis. */
export function analyzeErrorMessage(demo: boolean, reason: string): string {
  return demo ? `Demo analysis stopped — ${reason}` : `Analysis error: ${reason}`;
}

/** A live capture session beginning. */
export function liveStartMessage(demo: boolean, iface: string, captureFile: string): string {
  return demo
    ? `Demo capture session started — simulated vcan0 traffic · ${captureFile} is never written`
    : `Live capture started on ${iface} → ${captureFile}`;
}

/** One scored window predicted ANOMALY while a session is running. */
export function liveAnomalyMessage(demo: boolean, w: InferenceWindow): string {
  return demo
    ? `Demo anomaly event — illustrative prediction · window #${w.window_index} scored ${w.anomaly_score.toFixed(4)} from ${w.features.total_frames} simulated frames`
    : `Window #${w.window_index} classified ANOMALY — score ${w.anomaly_score.toFixed(4)}, ${w.features.total_frames} frames`;
}

/** A live capture ending with its final scoring run. */
export function liveStopMessage(demo: boolean, a: AnalysisResult): string {
  return demo
    ? `Demo capture session ended — scripted results · ${a.anomaly_count}/${a.windows_scored} windows marked anomalous · nothing stored`
    : `Capture stored: ${a.capture_file}. Final inference: ${a.anomaly_count}/${a.windows_scored} anomalous`;
}
