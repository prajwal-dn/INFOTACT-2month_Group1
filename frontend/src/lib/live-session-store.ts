// Remembers which live capture session is active so other pages (Overview)
// can follow it. Holds only the session id; all data comes from the backend.
import { useSyncExternalStore } from "react";

const STORAGE_KEY = "can_sentinel_active_live_session_id";

function getInitialActiveId(): string | null {
  try {
    if (typeof window !== "undefined" && window.localStorage) {
      return window.localStorage.getItem(STORAGE_KEY);
    }
  } catch {
    // ignore
  }
  return null;
}

let activeId: string | null = getInitialActiveId();
const listeners = new Set<() => void>();

export function setActiveLiveSession(id: string | null) {
  activeId = id;
  try {
    if (typeof window !== "undefined" && window.localStorage) {
      if (id) {
        window.localStorage.setItem(STORAGE_KEY, id);
      } else {
        window.localStorage.removeItem(STORAGE_KEY);
      }
    }
  } catch {
    // ignore
  }
  listeners.forEach((l) => l());
}

export function getActiveLiveSessionId(): string | null {
  return activeId;
}

export function useActiveLiveSessionId() {
  return useSyncExternalStore(
    (l) => {
      listeners.add(l);
      return () => listeners.delete(l);
    },
    () => activeId,
    () => null,
  );
}
