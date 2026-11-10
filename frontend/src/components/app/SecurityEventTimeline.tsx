/**
 * SecurityEventTimeline
 *
 * Renders a chronological (newest-first) list of SecurityTimelineEvents
 * derived from the live session via useSecurityTimeline.
 */
import { useEffect, useRef } from "react";
import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  Info,
  Radio,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Siren,
  XCircle,
  Zap,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Panel } from "@/components/app/primitives";
import { cn } from "@/lib/utils";
import type { TimelineCategory, TimelineEvent, TimelineSeverity } from "@/lib/use-security-timeline";

// ─── Colour / icon maps ───────────────────────────────────────────────────────

const SEVERITY_DOT: Record<TimelineSeverity, string> = {
  info:     "bg-cyan-500",
  normal:   "bg-emerald-500",
  warning:  "bg-amber-500",
  critical: "bg-destructive",
};

const SEVERITY_RING: Record<TimelineSeverity, string> = {
  info:     "ring-cyan-500/30",
  normal:   "ring-emerald-500/30",
  warning:  "ring-amber-500/30",
  critical: "ring-destructive/30",
};

const SEVERITY_TEXT: Record<TimelineSeverity, string> = {
  info:     "text-cyan-400",
  normal:   "text-emerald-500",
  warning:  "text-amber-500",
  critical: "text-destructive",
};

const CATEGORY_LABEL: Record<TimelineCategory, string> = {
  system:   "SYSTEM",
  normal:   "NORMAL",
  anomaly:  "ANOMALY",
  incident: "INCIDENT",
  response: "RESPONSE",
  recovery: "RECOVERY",
};

const CATEGORY_BADGE: Record<TimelineCategory, string> = {
  system:   "bg-cyan-500/15 text-cyan-400 border-cyan-500/30",
  normal:   "bg-emerald-500/15 text-emerald-400 border-emerald-500/30",
  anomaly:  "bg-amber-500/15 text-amber-400 border-amber-500/30",
  incident: "bg-destructive/15 text-destructive border-destructive/30",
  response: "bg-orange-500/15 text-orange-400 border-orange-500/30",
  recovery: "bg-teal-500/15 text-teal-400 border-teal-500/30",
};

function CategoryIcon({ category, severity, className }: { category: TimelineCategory; severity: TimelineSeverity; className?: string }) {
  const cls = cn("size-3.5", SEVERITY_TEXT[severity], className);
  switch (category) {
    case "system":   return <Radio className={cls} />;
    case "normal":   return <Activity className={cls} />;
    case "anomaly":  return <AlertTriangle className={cls} />;
    case "incident": return <ShieldAlert className={cls} />;
    case "response": return severity === "critical" ? <XCircle className={cls} /> : <Zap className={cls} />;
    case "recovery": return severity === "normal" ? <ShieldCheck className={cls} /> : <Shield className={cls} />;
    default:         return <Info className={cls} />;
  }
}

// ─── Timestamp formatter ─────────────────────────────────────────────────────

/** Format an ISO string as HH:MM:SS.mmm (UTC) */
function fmtTs(iso: string): string {
  try {
    const d = new Date(iso);
    const hh = String(d.getUTCHours()).padStart(2, "0");
    const mm = String(d.getUTCMinutes()).padStart(2, "0");
    const ss = String(d.getUTCSeconds()).padStart(2, "0");
    const ms = String(d.getUTCMilliseconds()).padStart(3, "0");
    return `${hh}:${mm}:${ss}.${ms}`;
  } catch {
    return iso.slice(11, 23);
  }
}

// ─── Single event row ─────────────────────────────────────────────────────────

function EventRow({ event }: { event: TimelineEvent }) {
  return (
    <div className="group flex gap-3 py-2.5 border-b border-border/40 last:border-0">
      {/* Dot + vertical line */}
      <div className="flex flex-col items-center pt-0.5 shrink-0">
        <span
          className={cn(
            "size-2 rounded-full ring-2",
            SEVERITY_DOT[event.severity],
            SEVERITY_RING[event.severity],
          )}
        />
        <span className="mt-1 w-px flex-1 bg-border/40 group-last:hidden" />
      </div>

      {/* Content */}
      <div className="min-w-0 flex-1 pb-2">
        {/* Row 1: timestamp + badges */}
        <div className="flex flex-wrap items-center gap-1.5 mb-0.5">
          <span className="font-mono text-[0.65rem] text-muted-foreground tabular-nums" title={event.timestamp}>
            {fmtTs(event.timestamp)}{" "}
            <span className="text-muted-foreground/50">UTC</span>
          </span>

          <span
            className={cn(
              "inline-flex items-center gap-1 rounded border px-1 py-px text-[0.6rem] font-semibold uppercase tracking-wide",
              CATEGORY_BADGE[event.category],
            )}
          >
            <CategoryIcon category={event.category} severity={event.severity} />
            {CATEGORY_LABEL[event.category]}
          </span>

          {event.incident_id && (
            <span className="rounded border border-border/60 bg-secondary/60 px-1 py-px font-mono text-[0.6rem] text-muted-foreground">
              {event.incident_id.slice(0, 8)}
            </span>
          )}

          {event.score != null && (
            <span className="rounded border border-amber-500/30 bg-amber-500/10 px-1 py-px font-mono text-[0.6rem] text-amber-400">
              Δ {event.score.toFixed(4)}
            </span>
          )}
        </div>

        {/* Row 2: title */}
        <p className={cn("text-xs font-semibold leading-snug", SEVERITY_TEXT[event.severity])}>
          {event.title}
        </p>

        {/* Row 3: description */}
        <p className="mt-0.5 text-[0.7rem] leading-relaxed text-muted-foreground">
          {event.description}
        </p>

        {/* Row 4: CAN IDs */}
        {event.can_ids && event.can_ids.length > 0 && (
          <div className="mt-1 flex flex-wrap gap-1">
            {event.can_ids.map((id) => (
              <span
                key={id}
                className="rounded border border-border/60 bg-secondary/60 px-1 py-px font-mono text-[0.6rem] text-foreground"
              >
                {id}
              </span>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

// ─── Main component ───────────────────────────────────────────────────────────

interface SecurityEventTimelineProps {
  events: TimelineEvent[];
  /** Pass true while capture is running so the "live" indicator renders. */
  capturing?: boolean;
}

export function SecurityEventTimeline({ events, capturing = false }: SecurityEventTimelineProps) {
  // Scroll the timeline's own container to the top (newest event) when new
  // events arrive — but ONLY if the user is already near the top of that
  // container.  We never call scrollIntoView() which would scroll the page.
  const containerRef = useRef<HTMLDivElement>(null);
  const prevCount = useRef(0);

  useEffect(() => {
    if (events.length > prevCount.current) {
      const el = containerRef.current;
      if (el && el.scrollTop < 120) {
        el.scrollTop = 0;
      }
    }
    prevCount.current = events.length;
  }, [events.length]);

  // Display newest first
  const displayEvents = [...events].reverse();

  const aside = (
    <div className="flex items-center gap-2">
      {capturing && (
        <span className="flex items-center gap-1 text-xs text-emerald-500">
          <span className="size-1.5 rounded-full bg-emerald-500 animate-pulse" />
          live
        </span>
      )}
      <span className="text-xs text-muted-foreground">
        {events.length} event{events.length !== 1 ? "s" : ""}
      </span>
    </div>
  );

  return (
    <Panel title="Security Event Timeline" aside={aside}>
      {events.length === 0 ? (
        <div className="flex flex-col items-center gap-2 py-8 text-center">
          <Siren className="size-6 text-muted-foreground/40" />
          <p className="text-sm text-muted-foreground">
            Waiting for live capture to start…
          </p>
          <p className="text-xs text-muted-foreground/60">
            Events will appear here as the backend processes CAN windows.
          </p>
        </div>
      ) : (
        <div ref={containerRef} className="max-h-[480px] overflow-y-auto pr-1">
          {displayEvents.map((ev) => (
            <EventRow key={ev.id} event={ev} />
          ))}
        </div>
      )}
    </Panel>
  );
}

