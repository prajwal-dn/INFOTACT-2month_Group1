import { beforeEach, describe, expect, it } from "vitest";

import { clearLog, getAuditLog, logEvent } from "@/lib/audit-log";

beforeEach(() => clearLog());

describe("Audit log", () => {
  it("records severity, demo flag and a parseable timestamp", () => {
    logEvent("ALERT", "Demo anomaly event — illustrative prediction", true);
    const [entry] = getAuditLog();
    expect(entry?.level).toBe("ALERT");
    expect(entry?.demo).toBe(true);
    expect(entry?.message).toBe("Demo anomaly event — illustrative prediction");
    expect(Number.isNaN(Date.parse(entry?.time ?? ""))).toBe(false);
  });

  it("keeps the newest entry first", () => {
    logEvent("INFO", "first", true);
    logEvent("INFO", "second", true);
    expect(getAuditLog().map((e) => e.message)).toEqual(["second", "first"]);
  });

  it("refuses a second entry for the same action", () => {
    logEvent("SUCCESS", "Demo analysis completed — scripted results", true, "analysis:demo-1");
    logEvent("SUCCESS", "Demo analysis completed — scripted results", true, "analysis:demo-1");
    expect(getAuditLog()).toHaveLength(1);
  });

  it("still records two separate actions that produced the same message", () => {
    logEvent("SUCCESS", "Demo analysis completed — scripted results", true, "analysis:demo-1");
    logEvent("SUCCESS", "Demo analysis completed — scripted results", true, "analysis:demo-2");
    expect(getAuditLog()).toHaveLength(2);
  });

  it("records an anomaly per session window, never twice for one window", () => {
    logEvent("ALERT", "Demo anomaly event — illustrative prediction", true, "live-anomaly:demo-live-1:4");
    logEvent("ALERT", "Demo anomaly event — illustrative prediction", true, "live-anomaly:demo-live-1:4");
    logEvent("ALERT", "Demo anomaly event — illustrative prediction", true, "live-anomaly:demo-live-1:5");
    expect(getAuditLog()).toHaveLength(2);
  });

  it("leaves backend entries unflagged", () => {
    logEvent("INFO", "Live capture started on vcan0 → capture.csv", false, "live-start:1");
    expect(getAuditLog()[0]?.demo).toBe(false);
  });

  it("empties the log on clear", () => {
    logEvent("INFO", "Demo capture session started — simulated vcan0 traffic", true, "live-start:1");
    clearLog();
    expect(getAuditLog()).toEqual([]);
  });
});
