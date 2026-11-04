import { useMemo } from "react";

import type { ApiClient } from "./client";
import { useBackendConfig, type BackendConfig } from "./config";
import { createDemoClient } from "./demo-client";
import { createHttpClient } from "./http-client";

let demo: ApiClient | null = null;
const getDemo = () => (demo ??= createDemoClient());

export function clientFor(config: BackendConfig): ApiClient {
  return config.mode === "demo" ? getDemo() : createHttpClient(config.baseUrl);
}

/** The active API client plus a cache-key scope for TanStack Query. */
export function useApi() {
  const config = useBackendConfig();
  return useMemo(
    () => ({ client: clientFor(config), config, scope: [config.mode, config.mode === "api" ? config.baseUrl : "demo"] as const }),
    [config],
  );
}

export * from "./client";
export * from "./schemas";
export { useBackendConfig, setConfig, DEFAULT_CONFIG } from "./config";
