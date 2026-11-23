// Lightweight pre-upload check only. Full validation and analysis happen in
// the Python backend (frequency_analyzer.load_capture).
import { ApiError } from "./client";

export const CAPTURE_HEADER = "timestamp_utc,interface,can_id,frame_format,flags,dlc,payload";
export const MAX_UPLOAD_BYTES = 50 * 1024 * 1024;

export async function validateCaptureHeader(file: File) {
  if (!/\.csv$/i.test(file.name)) throw new ApiError("Choose a .csv capture produced by can_sniffer.", 422);
  if (file.size > MAX_UPLOAD_BYTES) throw new ApiError("Capture is larger than 50 MB.", 413);
  const head = await file.slice(0, 256).text();
  const first = head.split(/\r?\n/)[0]?.trim();
  if (first !== CAPTURE_HEADER) {
    throw new ApiError(`Unexpected CSV header. Expected: ${CAPTURE_HEADER}`, 422);
  }
}
