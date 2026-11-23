import { describe, it, expect, beforeEach } from "vitest";
import {
  getActiveLiveSessionId,
  setActiveLiveSession,
} from "@/lib/live-session-store";
import { createDemoClient } from "@/lib/api/demo-client";

describe("Live Capture Session Persistence", () => {
  beforeEach(() => {
    localStorage.clear();
    setActiveLiveSession(null);
  });

  it("persists active session id to localStorage and restores it", () => {
    expect(getActiveLiveSessionId()).toBeNull();

    setActiveLiveSession("live_24ad05bf");
    expect(getActiveLiveSessionId()).toBe("live_24ad05bf");
    expect(localStorage.getItem("can_sentinel_active_live_session_id")).toBe("live_24ad05bf");

    setActiveLiveSession(null);
    expect(getActiveLiveSessionId()).toBeNull();
    expect(localStorage.getItem("can_sentinel_active_live_session_id")).toBeNull();
  });

  it("supports getActiveLiveSession in demo client", async () => {
    const demo = createDemoClient();
    const initialActive = await demo.getActiveLiveSession();
    expect(initialActive).toBeNull();

    const session = await demo.startLiveCapture();
    expect(session.state).toBe("capturing");

    const active = await demo.getActiveLiveSession();
    expect(active).not.toBeNull();
    expect(active?.id).toBe(session.id);
    expect(active?.state).toBe("capturing");
  });
});
