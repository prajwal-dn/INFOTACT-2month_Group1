import { createFileRoute } from "@tanstack/react-router";
import { Trash2 } from "lucide-react";

import { Button } from "@/components/ui/button";
import { DemoBadge } from "@/components/app/DemoNotice";
import { EmptyState, PageHeader } from "@/components/app/primitives";
import { clearLog, useAuditLog, type LogLevel } from "@/lib/audit-log";
import { pageHead } from "@/lib/head";
import { cn } from "@/lib/utils";

export const Route = createFileRoute("/audit")({
  head: () => pageHead("Audit log", "Session security audit log of captures, analyses and intrusion alerts."),
  component: Audit,
});

const LEVEL: Record<LogLevel, string> = {
  INFO: "text-primary bg-primary/10",
  SUCCESS: "text-success bg-success/10",
  WARN: "text-warning bg-warning/10",
  ALERT: "text-destructive bg-destructive/15",
};

function Audit() {
  const log = useAuditLog();
  return (
    <div>
      <PageHeader
        eyebrow="Security audit"
        title="Audit log"
        description="Events from this browser session: captures started and stored, analyses run and alerts raised."
        actions={
          <Button variant="ghost" onClick={clearLog} disabled={!log.length}>
            <Trash2 /> Clear
          </Button>
        }
      />
      {log.length ? (
        <div className="surface overflow-hidden p-2 font-mono text-xs">
          {log.map((e) => (
            <div key={e.id} className="flex items-start gap-4 rounded-lg px-3 py-2 hover:bg-secondary/50">
              <span className="shrink-0 tabular-nums text-muted-foreground">{e.time.slice(11, 19)}</span>
              <span className={cn("w-16 shrink-0 rounded px-1.5 text-center font-semibold", LEVEL[e.level])}>{e.level}</span>
              <span className="min-w-0 flex-1 break-words">{e.message}</span>
              {e.demo && <DemoBadge source="demo" />}
            </div>
          ))}
        </div>
      ) : (
        <EmptyState title="No events yet">Start a capture or run an analysis.</EmptyState>
      )}
    </div>
  );
}
