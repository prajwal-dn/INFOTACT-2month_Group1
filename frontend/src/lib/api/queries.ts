import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { useApi } from "./index";
import type { AnalysisResult } from "./schemas";

export function useStatus() {
  const { client, scope } = useApi();
  return useQuery({
    queryKey: [...scope, "status"],
    queryFn: () => client.getStatus(),
    refetchInterval: 15_000,
    retry: 0,
  });
}

export function usePresets() {
  const { client, scope } = useApi();
  return useQuery({ queryKey: [...scope, "presets"], queryFn: () => client.listPresets(), retry: 0 });
}

export function useAnalyses() {
  const { client, scope } = useApi();
  return useQuery({ queryKey: [...scope, "analyses"], queryFn: () => client.listAnalyses(), retry: 0 });
}

export function useAnalysis(id: string | undefined) {
  const { client, scope } = useApi();
  return useQuery({
    queryKey: [...scope, "analysis", id],
    queryFn: () => client.getAnalysis(id!),
    enabled: !!id,
    retry: 0,
  });
}

function useStoreAnalysis() {
  const qc = useQueryClient();
  const { scope } = useApi();
  return (a: AnalysisResult) => {
    qc.setQueryData([...scope, "analysis", a.id], a);
    qc.invalidateQueries({ queryKey: [...scope, "analyses"] });
  };
}

export function useAnalyzeCapture() {
  const { client } = useApi();
  const storeAnalysis = useStoreAnalysis();
  return useMutation({
    mutationFn: (input: { capture_path: string; origin?: "preset" | "path" }) => client.analyzeCapture(input),
    onSuccess: storeAnalysis,
  });
}

export function useUploadCapture() {
  const { client } = useApi();
  const storeAnalysis = useStoreAnalysis();
  return useMutation({ mutationFn: (file: File) => client.uploadCapture(file), onSuccess: storeAnalysis });
}

export function useLiveSession(id: string | null, polling: boolean) {
  const { client, scope } = useApi();
  return useQuery({
    queryKey: [...scope, "live", id],
    queryFn: () => client.getLiveSession(id!),
    enabled: !!id,
    refetchInterval: polling ? 1000 : false,
    retry: 0,
  });
}

export function useStartLive() {
  const { client } = useApi();
  return useMutation({ mutationFn: () => client.startLiveCapture() });
}

export function useStartLiveAttack() {
  const { client } = useApi();
  return useMutation({
    mutationFn: (input: { id: string; mode: 1 | 2 }) =>
      client.startLiveAttack(input.id, input.mode),
  });
}

export function useStopLiveAttack() {
  const { client } = useApi();
  return useMutation({
    mutationFn: (id: string) => client.stopLiveAttack(id),
  });
}

export function useStartLiveNormal() {
  const { client } = useApi();
  return useMutation({
    mutationFn: (input: { id: string; intervalMs?: number }) =>
      client.startLiveNormal(input.id, input.intervalMs),
  });
}

export function useStopLiveNormal() {
  const { client } = useApi();
  return useMutation({
    mutationFn: (id: string) => client.stopLiveNormal(id),
  });
}

export function useStopLiveSimulations() {
  const { client } = useApi();
  return useMutation({
    mutationFn: (id: string) => client.stopLiveSimulations(id),
  });
}

export function useStopLive() {
  const { client } = useApi();
  const storeAnalysis = useStoreAnalysis();
  return useMutation({ mutationFn: (id: string) => client.stopLiveCapture(id), onSuccess: storeAnalysis });
}

export function useDownloadReport() {
  const { client } = useApi();
  return useMutation({
    mutationFn: async (id: string) => {
      const { filename, csv } = await client.getReportCsv(id);
      const url = URL.createObjectURL(new Blob([csv], { type: "text/csv" }));
      const a = document.createElement("a");
      a.href = url;
      a.download = filename;
      a.click();
      URL.revokeObjectURL(url);
      return filename;
    },
  });
}


export function usePlanResponse() {
  const { client } = useApi();

  return useMutation({
    mutationFn: (input: { analysisId: string; incidentId: string }) =>
      client.planResponse(input.analysisId, input.incidentId),
  });
}

export function useActivateResponse() {
  const { client } = useApi();

  return useMutation({
    mutationFn: (input: { analysisId: string; incidentId: string }) =>
      client.activateResponse(input.analysisId, input.incidentId),
  });
}

export function useVerifyRecovery() {
  const { client } = useApi();

  return useMutation({
    mutationFn: (input: { analysisId: string; incidentId: string }) =>
      client.verifyRecovery(input.analysisId, input.incidentId),
  });
}
export function metricsOf(a: { windows_scored: number; anomaly_count: number; normal_count: number } | undefined) {
  if (!a) return null;
  return {
    total: a.windows_scored,
    normal: a.normal_count,
    anomalies: a.anomaly_count,
    rate: a.windows_scored ? (a.anomaly_count / a.windows_scored) * 100 : 0,
  };
}
