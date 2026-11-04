import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

vi.mock("@/lib/api", () => ({ useBackendConfig: () => ({ mode: "backend" }) }));
import { BusActivityWave } from "@/components/app/BusActivityWave";
import { FEATURE_COLUMNS, type InferenceWindow } from "@/lib/api/schemas";

const win = (i: number, prediction: "NORMAL" | "ANOMALY", total: number, x999 = 0): InferenceWindow => ({
  window_index: i, window_start_utc: `t${i}`, prediction, anomaly_score: 0.5,
  features: { ...Object.fromEntries(FEATURE_COLUMNS.map((c) => [c, 0])), total_frames: total, id_0x999_count: x999, max_id_share_pct: 99 } as InferenceWindow["features"],
});

describe("BusActivityWave", () => {
  it("shows idle state with no fabricated bars", () => {
    render(<BusActivityWave source={{ kind: "idle" }} />);
    expect(screen.getByTestId("bus-wave-idle")).toBeTruthy();
    expect(screen.queryAllByTestId("bus-wave-bar")).toHaveLength(0);
  });
  it("colours by backend prediction only, not by max_id_share_pct", () => {
    render(<BusActivityWave source={{ kind: "analysis", windows: [win(0, "NORMAL", 20), win(1, "ANOMALY", 80, 30)], excludedPartialWindow: null, dataSource: "backend" }} />);
    const bars = screen.getAllByTestId("bus-wave-bar");
    expect(bars.map((b) => b.getAttribute("data-prediction"))).toEqual(["NORMAL", "ANOMALY"]);
    expect(bars[1]?.getAttribute("data-0x999")).toBe("30");
    expect(bars[0]?.getAttribute("data-0x999")).toBeNull();
  });
  it("adds an unscored pending slot during live capture", () => {
    render(<BusActivityWave source={{ kind: "live", windows: [win(0, "NORMAL", 20)], pendingWindowIndex: 1, dataSource: "demo", capturing: true }} />);
    expect(screen.getAllByTestId("bus-wave-bar")).toHaveLength(1);
    expect(screen.getAllByTestId("bus-wave-pending")).toHaveLength(1);
  });
});
