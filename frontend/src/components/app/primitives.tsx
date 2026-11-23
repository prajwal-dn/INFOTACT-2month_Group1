import type { ReactNode } from "react";
import { AlertTriangle, Inbox } from "lucide-react";

import { cn } from "@/lib/utils";
import type { Prediction } from "@/lib/api/schemas";

export function PageHeader({
  eyebrow,
  title,
  description,
  actions,
}: {
  eyebrow: string;
  title: ReactNode;
  description?: ReactNode;
  actions?: ReactNode;
}) {
  return (
    <div className="mb-8 flex flex-wrap items-end justify-between gap-4 animate-rise">
      <div className="max-w-2xl">
        <div className="eyebrow mb-2">{eyebrow}</div>
        <h1 className="text-3xl font-semibold md:text-4xl">{title}</h1>
        {description && <p className="mt-2 text-sm leading-relaxed text-muted-foreground">{description}</p>}
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
    </div>
  );
}

export function Panel({ title, aside, children, className }: { title?: ReactNode; aside?: ReactNode; children: ReactNode; className?: string }) {
  return (
    <section className={cn("surface p-5", className)}>
      {(title || aside) && (
        <div className="mb-4 flex flex-wrap items-center justify-between gap-2">
          {title && <h2 className="text-sm font-semibold">{title}</h2>}
          {aside}
        </div>
      )}
      {children}
    </section>
  );
}

export function Verdict({ prediction }: { prediction: Prediction }) {
  const anomaly = prediction === "ANOMALY";
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded-md px-2 py-0.5 font-mono text-[0.68rem] font-semibold tracking-wide",
        anomaly ? "bg-destructive/15 text-destructive" : "bg-success/12 text-success",
      )}
    >
      <span className={cn("size-1.5 rounded-full", anomaly ? "bg-destructive" : "bg-success")} />
      {prediction}
    </span>
  );
}

export function EmptyState({ title, children, icon }: { title: string; children?: ReactNode; icon?: ReactNode }) {
  return (
    <div className="grid min-h-56 place-items-center rounded-xl border border-dashed p-8 text-center">
      <div className="max-w-sm">
        <div className="mx-auto mb-3 grid size-10 place-items-center rounded-full bg-secondary text-muted-foreground">
          {icon ?? <Inbox className="size-5" />}
        </div>
        <div className="font-medium">{title}</div>
        {children && <div className="mt-1 text-sm text-muted-foreground">{children}</div>}
      </div>
    </div>
  );
}

export function ErrorState({ error }: { error: unknown }) {
  return (
    <div className="flex items-start gap-3 rounded-xl border border-destructive/40 bg-destructive/10 p-4 text-sm">
      <AlertTriangle className="mt-0.5 size-4 shrink-0 text-destructive" />
      <div>
        <div className="font-semibold text-destructive">Backend request failed</div>
        <div className="mt-0.5 text-foreground/80">{error instanceof Error ? error.message : String(error)}</div>
      </div>
    </div>
  );
}

export const fmtTime = (iso: string) => iso.replace("T", " ").slice(0, 23);
export const fmtAgo = (iso: string) => {
  const s = Math.max(0, (Date.now() - Date.parse(iso)) / 1000);
  if (s < 60) return "just now";
  if (s < 3600) return `${Math.floor(s / 60)} min ago`;
  if (s < 86400) return `${Math.floor(s / 3600)} h ago`;
  return new Date(iso).toLocaleDateString();
};
