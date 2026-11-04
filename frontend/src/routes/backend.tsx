import { useState } from "react";
import { createFileRoute } from "@tanstack/react-router";
import { FlaskConical, Loader2, PlugZap } from "lucide-react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { PageHeader, Panel } from "@/components/app/primitives";
import { setConfig, useBackendConfig } from "@/lib/api";
import { createHttpClient } from "@/lib/api/http-client";
import { endpoints } from "@/lib/api/endpoints";
import { pageHead } from "@/lib/head";
import { cn } from "@/lib/utils";

export const Route = createFileRoute("/backend")({
  head: () => pageHead("Backend connection", "Switch between labelled demo mode and the CAN-Sentinel FastAPI backend."),
  component: Backend,
});

function Backend() {
  const config = useBackendConfig();
  const [url, setUrl] = useState(config.baseUrl);
  const [testing, setTesting] = useState(false);

  const test = async () => {
    setTesting(true);
    try {
      const s = await createHttpClient(url).getStatus();
      toast.success("Backend reachable", { description: `${s.interface.name} ${s.interface.state} · model ${s.model.loaded ? "loaded" : "missing"}` });
    } catch (e) {
      toast.error("Connection failed", { description: (e as Error).message });
    } finally {
      setTesting(false);
    }
  };

  const option = (mode: "demo" | "api", title: string, desc: string, Icon: typeof PlugZap) => (
    <button
      type="button"
      onClick={() => setConfig({ mode, baseUrl: url })}
      className={cn("surface flex items-start gap-4 p-5 text-left transition-all hover:border-primary/40", config.mode === mode && "border-primary/60 glow-primary")}
    >
      <Icon className={cn("mt-0.5 size-5", mode === "demo" ? "text-demo" : "text-primary")} />
      <span>
        <span className="block font-semibold">{title}</span>
        <span className="mt-1 block text-sm text-muted-foreground">{desc}</span>
      </span>
    </button>
  );

  return (
    <div className="space-y-6">
      <PageHeader eyebrow="Settings" title="Backend connection" description="The Linux Python pipeline is the source of truth. This site only displays what it returns." />
      <div className="grid gap-4 md:grid-cols-2">
        {option("demo", "Demo mode", "Scripted, clearly labelled sample data. Nothing is captured or scored.", FlaskConical)}
        {option("api", "FastAPI backend", "Live data from the CAN-Sentinel service running on the Linux host.", PlugZap)}
      </div>
      <Panel title="Backend URL">
        <div className="flex flex-wrap gap-2">
          <Input value={url} onChange={(e) => setUrl(e.target.value)} className="max-w-md font-mono text-xs" aria-label="Backend URL" />
          <Button variant="secondary" onClick={() => setConfig({ mode: config.mode, baseUrl: url })}>Save</Button>
          <Button variant="outline" onClick={test} disabled={testing}>
            {testing && <Loader2 className="animate-spin" />} Test connection
          </Button>
        </div>
        <p className="mt-3 text-xs text-muted-foreground">The service must allow this site's address in its CORS settings.</p>
      </Panel>
      <Panel title="Expected endpoints">
        <ul className="grid gap-1 font-mono text-xs text-muted-foreground sm:grid-cols-2">
          {[
            ["GET", endpoints.status()],
            ["GET", endpoints.presets()],
            ["GET", endpoints.analyses()],
            ["POST", endpoints.analyses()],
            ["POST", endpoints.upload()],
            ["GET", endpoints.analysis("{id}")],
            ["GET", endpoints.report("{id}")],
            ["POST", endpoints.liveStart()],
            ["GET", endpoints.live("{id}")],
            ["POST", endpoints.liveStop("{id}")],
          ].map(([m, p]) => (
            <li key={`${m}${p}`}>
              <span className="text-primary">{m}</span> {decodeURIComponent(p ?? "")}
            </li>
          ))}
        </ul>
      </Panel>
    </div>
  );
}
