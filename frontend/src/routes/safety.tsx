import { createFileRoute } from "@tanstack/react-router";
import { ShieldCheck } from "lucide-react";

import { PageHeader, Panel } from "@/components/app/primitives";
import { pageHead } from "@/lib/head";

export const Route = createFileRoute("/safety")({
  head: () => pageHead("Safety & limits", "Safety rules and known limitations of the CAN-Sentinel prototype."),
  component: Safety,
});

const RULES = [
  "All capture and attack simulation runs only on the isolated virtual interface vcan0.",
  "Never run attack simulations against a physical vehicle, live automotive bus or network without explicit authorization.",
  "Captures from any interface other than vcan0 are rejected by the backend.",
];
const LIMITS = [
  "Target sending intervals are not exact timing guarantees; VM scheduling and user-space capture add delays and outliers.",
  "Timestamps are taken in user space, not hardware-level bus timestamps.",
  "The model uses 1,000 ms windows and may exclude a possibly incomplete final window.",
  "Passing tests and successful captures do not prove real-world detection accuracy.",
];

function Safety() {
  return (
    <div className="space-y-6">
      <PageHeader eyebrow="Responsible use" title="Safety & limitations" />
      <Panel title="Safety rules">
        <ul className="space-y-2">
          {RULES.map((r) => (
            <li key={r} className="flex gap-3 text-sm"><ShieldCheck className="mt-0.5 size-4 shrink-0 text-success" />{r}</li>
          ))}
        </ul>
      </Panel>
      <Panel title="Known limitations">
        <ul className="list-disc space-y-2 pl-5 text-sm text-muted-foreground">
          {LIMITS.map((l) => <li key={l}>{l}</li>)}
        </ul>
      </Panel>
    </div>
  );
}
