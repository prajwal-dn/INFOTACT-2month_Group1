// Remembers which live capture session is active so other pages (Overview)
// can follow it. Holds only the session id; all data comes from the backend.
import { useSyncExternalStore } from "react";

let activeId: string | null = null;
const listeners = new Set<() => void>();

export function setActiveLiveSession(id: string | null) {
  activeId = id;
  listeners.forEach((l) => l());
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
