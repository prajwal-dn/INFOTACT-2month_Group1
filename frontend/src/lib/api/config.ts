// Backend connection settings, persisted in the browser.
import { useSyncExternalStore } from "react";

import type { BackendMode } from "./client";

export interface BackendConfig {
  mode: BackendMode;
  baseUrl: string;
}

const KEY = "can-sentinel.backend";
const envUrl = (import.meta.env["VITE_CAN_SENTINEL_API_URL"] as string | undefined) ?? "";

export const DEFAULT_CONFIG: BackendConfig = {
  mode: "demo",
  baseUrl: envUrl || "http://localhost:8000",
};

let current: BackendConfig = DEFAULT_CONFIG;
let loaded = false;
const listeners = new Set<() => void>();

function load() {
  if (loaded || typeof window === "undefined") return;
  loaded = true;
  try {
    const raw = window.localStorage.getItem(KEY);
    if (raw) {
      const parsed = JSON.parse(raw) as Partial<BackendConfig>;
      current = {
        mode: parsed.mode === "api" ? "api" : "demo",
        baseUrl: typeof parsed.baseUrl === "string" && parsed.baseUrl ? parsed.baseUrl : DEFAULT_CONFIG.baseUrl,
      };
    }
  } catch {
    /* ignore corrupt settings */
  }
}

export function getConfig(): BackendConfig {
  load();
  return current;
}

export function setConfig(next: BackendConfig) {
  current = next;
  try {
    window.localStorage.setItem(KEY, JSON.stringify(next));
  } catch {
    /* storage unavailable */
  }
  listeners.forEach((l) => l());
}

export function useBackendConfig(): BackendConfig {
  return useSyncExternalStore(
    (cb) => {
      listeners.add(cb);
      return () => listeners.delete(cb);
    },
    getConfig,
    () => DEFAULT_CONFIG,
  );
}
