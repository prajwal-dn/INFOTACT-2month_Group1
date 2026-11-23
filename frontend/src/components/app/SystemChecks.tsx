import { CheckCircle2, CircleDashed, FlaskConical, XCircle } from "lucide-react";

import { cn } from "@/lib/utils";
import type { SystemStatus } from "@/lib/api/schemas";

export interface Check {
  label: string;
  detail: string;
  ok: boolean | null;
  demo?: boolean;
}

/** The same pre-flight checks the desktop dashboard ran before recording. */
export function checksFor(status: SystemStatus | undefined): Check[] {
  if (status?.data_source === "demo") {
    return [
      {
        label: "Virtual interface",
        detail: "Demo interface · not connected to vcan0",
        ok: null,
        demo: true,
      },
      { label: "CAN sniffer", detail: "Not used in Demo Mode", ok: null, demo: true },
      {
        label: "Saved model",
        detail: "Isolation Forest not running · illustrative predictions",
        ok: null,
        demo: true,
      },
    ];
  }
  return [
    {
      label: "Virtual interface",
      detail: status
        ? `${status.interface.name} is ${status.interface.state}`
        : "Waiting for backend",
      ok: status ? status.interface.state === "UP" : null,
    },
    {
      label: "CAN sniffer",
      detail: status
        ? status.sniffer.built
          ? status.sniffer.path
          : `Not built: ${status.sniffer.path}`
        : "Waiting for backend",
      ok: status ? status.sniffer.built : null,
    },
    {
      label: "Saved model",
      detail: status
        ? status.model.loaded
          ? status.model.path
          : `Unavailable: ${status.model.path}`
        : "Waiting for backend",
      ok: status ? status.model.loaded : null,
    },
  ];
}

export function SystemChecks({ status }: { status: SystemStatus | undefined }) {
  return (
    <ul className="space-y-2">
      {checksFor(status).map((c) => (
        <li
          key={c.label}
          className="flex items-start gap-3 rounded-lg border bg-secondary/30 px-3 py-2.5"
        >
          {c.demo ? (
            <FlaskConical className="mt-0.5 size-4 shrink-0 text-demo" />
          ) : c.ok === null ? (
            <CircleDashed className="mt-0.5 size-4 shrink-0 animate-spin text-muted-foreground" />
          ) : c.ok ? (
            <CheckCircle2 className="mt-0.5 size-4 shrink-0 text-success" />
          ) : (
            <XCircle className="mt-0.5 size-4 shrink-0 text-destructive" />
          )}
          <div className="min-w-0">
            <div className="text-sm font-medium">{c.label}</div>
            <div
              className={cn(
                "break-all font-mono text-[0.7rem] text-muted-foreground",
                c.ok === false && "text-destructive",
              )}
              title={c.detail}
            >
              {c.detail}
            </div>
          </div>
        </li>
      ))}
    </ul>
  );
}
