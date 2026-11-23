import { Link } from "@tanstack/react-router";
import { FlaskConical } from "lucide-react";

import { cn } from "@/lib/utils";
import { useBackendConfig } from "@/lib/api";
import type { DataSource } from "@/lib/api/schemas";

/** Small inline tag for any value that came from demo data. */
export function DemoBadge({ className, source }: { className?: string; source?: DataSource | undefined }) {
  const { mode } = useBackendConfig();
  if ((source ?? (mode === "demo" ? "demo" : "backend")) !== "demo") return null;
  return (
    <span
      className={cn(
        "demo-stripes inline-flex items-center gap-1 rounded-md border border-demo/40 px-1.5 py-0.5 font-mono text-[0.6rem] font-bold uppercase tracking-[0.14em] text-demo",
        className,
      )}
      title="Scripted demo data — not real vcan0 traffic or model output"
    >
      <FlaskConical className="size-3" /> Demo data
    </span>
  );
}

/** Full-width banner shown on every page while demo mode is active. */
export function DemoBanner() {
  const { mode } = useBackendConfig();
  if (mode !== "demo") return null;
  return (
    <div className="demo-stripes flex flex-wrap items-center gap-x-3 gap-y-1 border-b border-demo/30 px-4 py-2 text-xs text-demo md:px-8">
      <FlaskConical className="size-4 shrink-0" />
      <span className="font-mono font-bold uppercase tracking-[0.16em]">Demo mode</span>
      <span className="text-foreground/80">
        Values are scripted for illustration. No CAN traffic is captured and the Isolation Forest model is not running.
      </span>
      <Link to="/backend" className="ml-auto font-semibold underline-offset-4 hover:underline">
        Connect backend →
      </Link>
    </div>
  );
}
