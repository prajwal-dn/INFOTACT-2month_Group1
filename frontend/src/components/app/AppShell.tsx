import { useEffect, useState, type ReactNode } from "react";
import { Link, useRouterState } from "@tanstack/react-router";
import {
  Activity,
  FileSearch,
  Gauge,
  History,
  PlugZap,
  Radio,
  ScrollText,
  ShieldCheck,
} from "lucide-react";

import { cn } from "@/lib/utils";
import { useBackendConfig } from "@/lib/api";
import { useStatus } from "@/lib/api/queries";
import { DemoBanner } from "./DemoNotice";

const NAV = [
  { to: "/", label: "Overview", icon: Gauge },
  { to: "/live", label: "Live monitor", icon: Radio },
  { to: "/analyze", label: "Analyze capture", icon: FileSearch },
  { to: "/analyses", label: "Analyses", icon: History },
  { to: "/audit", label: "Audit log", icon: ScrollText },
  { to: "/backend", label: "Backend", icon: PlugZap },
  { to: "/safety", label: "Safety & limits", icon: ShieldCheck },
] as const;

function Brand() {
  return (
    <Link to="/" className="flex items-center gap-3 px-2">
      <svg viewBox="0 0 32 32" className="size-9" aria-hidden>
        <defs>
          <linearGradient id="cs-g" x1="0" y1="0" x2="1" y2="1">
            <stop offset="0" stopColor="var(--primary)" />
            <stop offset="1" stopColor="var(--success)" />
          </linearGradient>
        </defs>
        <path d="M16 2 28 9v14l-12 7-12-7V9z" fill="none" stroke="url(#cs-g)" strokeWidth="2" />
        <path d="M8 17h4l2-5 4 9 2-4h4" fill="none" stroke="url(#cs-g)" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
      </svg>
      <div className="leading-tight">
        <div className="font-display text-[0.95rem] font-semibold tracking-tight">CAN-Sentinel</div>
        <div className="eyebrow !text-[0.58rem]">ECU intrusion detection</div>
      </div>
    </Link>
  );
}

function Clock() {
  const [now, setNow] = useState<string | null>(null);
  useEffect(() => {
    const tick = () => setNow(new Date().toISOString().slice(11, 19));
    tick();
    const t = setInterval(tick, 1000);
    return () => clearInterval(t);
  }, []);
  return <span className="font-mono text-xs tabular-nums text-muted-foreground">{now ?? "--:--:--"} UTC</span>;
}

function BackendPill() {
  const { mode, baseUrl } = useBackendConfig();
  const status = useStatus();
  const state =
    mode === "demo"
      ? { label: "Demo backend", tone: "border-demo/40 text-demo", dot: "bg-demo" }
      : status.isError
        ? { label: "Backend offline", tone: "border-destructive/40 text-destructive", dot: "bg-destructive" }
        : status.isSuccess && status.data.data_source === "backend"
          ? { label: "Backend connected", tone: "border-success/40 text-success", dot: "bg-success animate-pulse-dot" }
          : { label: "Connecting…", tone: "border-border text-muted-foreground", dot: "bg-muted-foreground animate-pulse-dot" };
  return (
    <Link
      to="/backend"
      title={mode === "api" ? baseUrl : "Scripted demo data"}
      className={cn("flex items-center gap-2 rounded-full border bg-card/60 px-3 py-1 text-xs font-medium", state.tone)}
    >
      <span className={cn("size-1.5 rounded-full", state.dot)} />
      {state.label}
    </Link>
  );
}

function InterfacePill() {
  const { mode } = useBackendConfig();
  const status = useStatus();
  if (mode === "demo" || status.data?.data_source === "demo") {
    return (
      <span
        title="Demo Mode: no Linux virtual CAN interface is connected"
        className="hidden items-center gap-2 rounded-full border border-demo/40 bg-card/60 px-3 py-1 font-mono text-xs text-demo sm:flex"
      >
        <span className="size-1.5 rounded-full bg-demo" />
        Demo interface · not connected
      </span>
    );
  }
  const s = status.isSuccess ? status.data.interface : undefined;
  const up = s?.state === "UP";
  return (
    <span className="hidden items-center gap-2 rounded-full border bg-card/60 px-3 py-1 font-mono text-xs text-muted-foreground sm:flex">
      <span className={cn("size-1.5 rounded-full", up ? "bg-success" : s ? "bg-destructive" : "bg-muted-foreground")} />
      {s ? `${s.name} ${s.state}` : status.isError ? "vcan0 unknown" : "vcan0 —"}
    </span>
  );
}

export function AppShell({ children }: { children: ReactNode }) {
  const pathname = useRouterState({ select: (s) => s.location.pathname });
  const isActive = (to: string) => (to === "/" ? pathname === "/" : pathname.startsWith(to));

  return (
    <div className="app-canvas flex min-h-screen">
      <aside className="sticky top-0 hidden h-screen w-64 shrink-0 flex-col border-r border-sidebar-border bg-sidebar/80 px-3 py-5 backdrop-blur lg:flex">
        <Brand />
        <nav className="mt-8 flex flex-col gap-0.5">
          {NAV.map(({ to, label, icon: Icon }) => (
            <Link
              key={to}
              to={to}
              className={cn(
                "group flex items-center gap-3 rounded-lg px-3 py-2 text-sm text-sidebar-foreground/70 transition-colors hover:bg-sidebar-accent hover:text-sidebar-accent-foreground",
                isActive(to) && "bg-sidebar-accent text-sidebar-accent-foreground",
              )}
            >
              <Icon className={cn("size-4", isActive(to) ? "text-primary" : "text-muted-foreground group-hover:text-foreground")} />
              {label}
              {isActive(to) && <span className="ml-auto h-4 w-0.5 rounded-full bg-primary" />}
            </Link>
          ))}
        </nav>
        <div className="mt-auto rounded-xl border border-sidebar-border bg-card/50 p-3 text-[0.7rem] leading-relaxed text-muted-foreground">
          <div className="mb-1 flex items-center gap-1.5 font-semibold text-foreground">
            <Activity className="size-3.5 text-primary" /> Virtual bus only
          </div>
          Capture and detection run in the Linux Python backend on isolated <span className="font-mono">vcan0</span>.
        </div>
      </aside>

      <div className="flex min-w-0 flex-1 flex-col">
        <header className="sticky top-0 z-30 border-b bg-background/75 backdrop-blur-xl">
          <div className="flex h-14 items-center gap-3 px-4 md:px-8">
            <div className="lg:hidden">
              <Brand />
            </div>
            <div className="ml-auto flex items-center gap-2.5">
              <InterfacePill />
              <BackendPill />
              <span className="hidden md:inline">
                <Clock />
              </span>
            </div>
          </div>
          <nav className="flex gap-1 overflow-x-auto px-3 pb-2 lg:hidden">
            {NAV.map(({ to, label }) => (
              <Link
                key={to}
                to={to}
                className={cn(
                  "whitespace-nowrap rounded-md px-3 py-1.5 text-xs text-muted-foreground",
                  isActive(to) && "bg-secondary text-foreground",
                )}
              >
                {label}
              </Link>
            ))}
          </nav>
          <DemoBanner />
        </header>
        <main className="mx-auto w-full max-w-[1400px] flex-1 px-4 py-8 md:px-8">{children}</main>
        <footer className="border-t px-4 py-4 text-xs text-muted-foreground md:px-8">
          <div className="mx-auto flex max-w-[1400px] flex-wrap justify-between gap-2">
            <span>Prototype · Virtual-CAN captures only · Model accuracy is not independently validated</span>
            <span className="font-mono">CAN-Sentinel web · Isolation Forest · vcan0-only</span>
          </div>
        </footer>
      </div>
    </div>
  );
}
