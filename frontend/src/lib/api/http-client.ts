// FastAPI implementation of ApiClient. Every response is validated against
// the shared zod schemas so contract drift surfaces as a clear error.
import { z } from "zod";

import { ApiError, type ApiClient } from "./client";
import { endpoints, joinUrl } from "./endpoints";
import {
  AnalysisResult,
  AnalysisSummary,
  ApiErrorBody,
  CapturePreset,
  LiveSession,
  SystemStatus,
} from "./schemas";

const TIMEOUT_MS = 15_000;

export function createHttpClient(baseUrl: string, fetchImpl: typeof fetch = fetch): ApiClient {
  async function send(path: string, init: RequestInit = {}): Promise<Response> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
    let res: Response;
    try {
      res = await fetchImpl(joinUrl(baseUrl, path), {
        ...init,
        signal: controller.signal,
        headers: { Accept: "application/json", ...(init.headers ?? {}) },
      });
    } catch (err) {
      throw new ApiError(
        `Cannot reach the CAN-Sentinel backend at ${baseUrl}. Is the FastAPI service running and allowing this site (CORS)?`,
        undefined,
        "network",
      );
    } finally {
      clearTimeout(timer);
    }
    if (!res.ok) {
      let detail = res.statusText;
      try {
        const parsed = ApiErrorBody.safeParse(await res.clone().json());
        if (parsed.success) detail = typeof parsed.data.detail === "string" ? parsed.data.detail : JSON.stringify(parsed.data.detail);
      } catch {
        /* non-JSON error body */
      }
      throw new ApiError(detail || `Request failed (${res.status})`, res.status, "http");
    }
    return res;
  }

  async function json<T>(schema: z.ZodType<T>, path: string, init?: RequestInit): Promise<T> {
    const res = await send(path, init);
    const parsed = schema.safeParse(await res.json());
    if (!parsed.success) {
      throw new ApiError(
        `Backend response for ${path} does not match the expected contract: ${parsed.error.issues[0]?.path.join(".")} ${parsed.error.issues[0]?.message}`,
        res.status,
        "contract",
      );
    }
    return parsed.data;
  }

  const post = (body?: unknown): RequestInit => ({
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: body === undefined ? null : JSON.stringify(body),
  });

  return {
    mode: "api",
    getStatus: () => json(SystemStatus, endpoints.status()),
    listPresets: () => json(z.array(CapturePreset), endpoints.presets()),
    listAnalyses: () => json(z.array(AnalysisSummary), endpoints.analyses()),
    getAnalysis: (id) => json(AnalysisResult, endpoints.analysis(id)),
    analyzeCapture: (input) => json(AnalysisResult, endpoints.analyses(), post(input)),
    uploadCapture: (file) => {
      const form = new FormData();
      form.append("file", file, file.name);
      return json(AnalysisResult, endpoints.upload(), { method: "POST", body: form });
    },
    getReportCsv: async (id) => {
      const res = await send(endpoints.report(id), { headers: { Accept: "text/csv" } });
      const disposition = res.headers.get("content-disposition") ?? "";
      const filename = /filename="?([^";]+)"?/.exec(disposition)?.[1] ?? `${id}_inference.csv`;
      return { filename, csv: await res.text() };
    },
    startLiveCapture: () => json(LiveSession, endpoints.liveStart(), post()),
    getLiveSession: (id) => json(LiveSession, endpoints.live(id)),
    stopLiveCapture: (id) => json(AnalysisResult, endpoints.liveStop(id), post()),
  };
}
