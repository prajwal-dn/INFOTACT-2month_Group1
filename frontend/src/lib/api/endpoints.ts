// FastAPI route table. Keep in sync with docs/api-contract.md.
export const endpoints = {
  status: () => "/api/status",
  presets: () => "/api/presets",
  analyses: () => "/api/analyses",
  analysis: (id: string) => `/api/analyses/${encodeURIComponent(id)}`,
  upload: () => "/api/analyses/upload",
  report: (id: string) => `/api/analyses/${encodeURIComponent(id)}/report.csv`,
  incidents: () => "/api/incidents",
  liveStart: () => "/api/live/start",
  live: (id: string) => `/api/live/${encodeURIComponent(id)}`,
  liveStop: (id: string) => `/api/live/${encodeURIComponent(id)}/stop`,
  liveAttack: (id: string) => `/api/live/${encodeURIComponent(id)}/attack`,
  liveAttackStop: (id: string) => `/api/live/${encodeURIComponent(id)}/attack/stop`,
  liveNormal: (id: string) => `/api/live/${encodeURIComponent(id)}/normal`,
  liveNormalStop: (id: string) => `/api/live/${encodeURIComponent(id)}/normal/stop`,
  liveSimulationsStop: (id: string) => `/api/live/${encodeURIComponent(id)}/simulations/stop`,

  responsePlan: (analysisId: string, incidentId: string) =>
  `/api/analyses/${encodeURIComponent(analysisId)}/incidents/${encodeURIComponent(incidentId)}/response/plan`,

  responseActivate: (analysisId: string, incidentId: string) =>
  `/api/analyses/${encodeURIComponent(analysisId)}/incidents/${encodeURIComponent(incidentId)}/response/activate`,

  responseVerify: (analysisId: string, incidentId: string) =>
  `/api/analyses/${encodeURIComponent(analysisId)}/incidents/${encodeURIComponent(incidentId)}/response/verify`,
} as const;

export function joinUrl(baseUrl: string, path: string) {
  return `${baseUrl.replace(/\/+$/, "")}${path}`;
}
