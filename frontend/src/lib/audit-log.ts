// Session-scoped security audit log (mirrors the desktop SecurityLogWidget).
import { useSyncExternalStore } from "react";

export type LogLevel = "INFO" | "SUCCESS" | "WARN" | "ALERT";
export interface LogEvent {
  id: number;
  time: string;
  level: LogLevel;
  message: string;
  demo: boolean;
  /** Caller-supplied id so one action can never append the same entry twice. */
  key?: string;
}

let events: LogEvent[] = [];
let nextId = 1;
const listeners = new Set<() => void>();
const EMPTY: LogEvent[] = [];

export function logEvent(level: LogLevel, message: string, demo: boolean, key?: string) {
  if (key && events.some((e) => e.key === key)) return;
  const event: LogEvent = { id: nextId++, time: new Date().toISOString(), level, message, demo };
  if (key !== undefined) event.key = key;
  events = [event, ...events].slice(0, 500);
  listeners.forEach((l) => l());
}

/** The current log, newest first. Lets non-React code (and tests) read it. */
export function getAuditLog(): LogEvent[] {
  return events;
}

export function clearLog() {
  events = [];
  listeners.forEach((l) => l());
}

export function useAuditLog() {
  return useSyncExternalStore(
    (cb) => {
      listeners.add(cb);
      return () => listeners.delete(cb);
    },
    () => events,
    () => EMPTY,
  );
}
