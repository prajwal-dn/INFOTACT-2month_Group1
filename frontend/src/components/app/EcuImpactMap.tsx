import {
  Activity,
  AlertTriangle,
  CarFront,
  Gauge,
  RadioTower,
  Thermometer,
} from "lucide-react";

import type { Incident } from "@/lib/api/schemas";

interface EcuImpactMapProps {
  incidents: Incident[];
}

const SIGNALS = [
  {
    id: "0x100",
    name: "Engine RPM",
    description: "Simulated engine-speed signal",
    value: "3000 RPM",
    icon: Gauge,
  },
  {
    id: "0x101",
    name: "Vehicle Speed",
    description: "Simulated vehicle-speed signal",
    value: "60 km/h",
    icon: CarFront,
  },
  {
    id: "0x102",
    name: "Coolant Temperature",
    description: "Simulated coolant-temperature signal",
    value: "90 °C",
    icon: Thermometer,
  },
];

export function EcuImpactMap({ incidents }: EcuImpactMapProps) {
  const unmappedIncidents = incidents.filter((incident) =>
    incident.affected_can_ids.includes("0x999"),
  );

  const mappedSignals = SIGNALS.map((signal) => {
    const related = incidents.filter((incident) =>
      incident.affected_can_ids.includes(signal.id),
    );

    return {
      ...signal,
      incidents: related,
      affected: related.length > 0,
    };
  });

  const affectedCount = mappedSignals.filter(
    (signal) => signal.affected,
  ).length;

  return (
    <section className="space-y-4 rounded-xl border bg-card p-5">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
            Sentinel X / Vehicle telemetry
          </p>
          <h2 className="text-xl font-semibold">
            ECU & Signal Impact Map
          </h2>
          <p className="text-sm text-muted-foreground">
            Simulated vehicle signals associated with correlated incidents
          </p>
        </div>

        <span className="rounded-lg border bg-secondary px-3 py-2 text-sm">
          {affectedCount} / {SIGNALS.length} signals affected
        </span>
      </div>

      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
        {mappedSignals.map((signal) => {
          const Icon = signal.icon;
          const highestSeverity = signal.incidents.some(
            (incident) => incident.severity === "HIGH",
          )
            ? "HIGH"
            : signal.incidents.some(
                  (incident) => incident.severity === "MEDIUM",
                )
              ? "MEDIUM"
              : signal.affected
                ? "REVIEW"
                : "NORMAL";

          return (
            <article
              key={signal.id}
              className={`rounded-xl border p-4 ${
                signal.affected
                  ? "border-destructive/50 bg-destructive/5"
                  : "bg-secondary/30"
              }`}
            >
              <div className="flex items-start justify-between gap-2">
                <Icon
                  className={`size-6 ${
                    signal.affected
                      ? "text-destructive"
                      : "text-muted-foreground"
                  }`}
                />

                <span
                  className={`rounded-md border px-2 py-1 text-xs font-semibold ${
                    signal.affected
                      ? "border-destructive/30 text-destructive"
                      : "text-muted-foreground"
                  }`}
                >
                  {highestSeverity}
                </span>
              </div>

              <h3 className="mt-4 font-semibold">{signal.name}</h3>
              <p className="text-xs text-muted-foreground">
                {signal.description}
              </p>

              <div className="mt-4 flex items-center justify-between border-t pt-3">
                <span className="font-mono text-sm">{signal.id}</span>
                <span className="text-sm font-medium">{signal.value}</span>
              </div>

              <p className="mt-3 text-xs text-muted-foreground">
                {signal.affected
                  ? `${signal.incidents.length} correlated incident(s)`
                  : "No correlated incident"}
              </p>
            </article>
          );
        })}
      </div>

      <div
        className={`rounded-lg border p-4 ${
          unmappedIncidents.length
            ? "border-orange-500/40 bg-orange-500/5"
            : "bg-secondary/30"
        }`}
      >
        <div className="flex items-center gap-3">
          {unmappedIncidents.length ? (
            <AlertTriangle className="size-6 text-orange-500" />
          ) : (
            <RadioTower className="size-6 text-muted-foreground" />
          )}

          <div className="min-w-0 flex-1">
            <p className="font-semibold">Unmapped / Extended CAN Traffic</p>
            <p className="font-mono text-xs text-muted-foreground">
              CAN ID 0x999
            </p>
          </div>

          <span className="text-xs font-semibold">
            {unmappedIncidents.length
              ? `${unmappedIncidents.length} incident(s)`
              : "No incident"}
          </span>
        </div>

        <p className="mt-2 text-xs text-muted-foreground">
          0x999 is an extended CAN ID used by the project's attack
          simulator. It is not assigned to a simulated vehicle signal.
        </p>
      </div>

      <p className="text-xs text-muted-foreground">
        Impact is inferred from CAN IDs recorded in correlated incidents.
        This visualization represents simulated signals, not verified
        physical ECU health or vehicle compromise.
      </p>
    </section>
  );
}
