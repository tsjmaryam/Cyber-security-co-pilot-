import { StatusPill } from "./StatusPill";
import { toneForSeverity } from "@/lib/view-model";
import type { QueueItem } from "@/lib/view-model";

export function QueuePanel({
  queue,
  selectedIncidentId,
  queueLoading,
  queueError,
  onSelectIncident,
}: {
  queue: QueueItem[];
  selectedIncidentId: string | null;
  queueLoading: boolean;
  queueError: string | null;
  onSelectIncident: (incidentId: string) => void;
}) {
  return (
    <section className="queue-panel">
      <div className="rail-heading">
        <span>Incident queue</span>
        <strong>{queue.length} loaded</strong>
      </div>
      {queueLoading ? <p className="queue-error">Loading incidents...</p> : null}
      {queueError ? <p className="queue-error">{queueError}</p> : null}
      <div className="queue-list">
        {queue.map((item) => (
          <button
            className={`queue-item${item.id === selectedIncidentId ? " queue-item--active" : ""}`}
            key={item.id}
            onClick={() => onSelectIncident(item.id)}
            type="button"
          >
            <div className="queue-primary">
              <strong>{item.label}</strong>
              <p>{item.site}</p>
              {item.timestamp ? <small className="queue-timestamp">{item.timestamp}</small> : null}
            </div>
            <div className="queue-meta">
              <StatusPill tone={toneForSeverity(item.severity)}>{item.severity}</StatusPill>
              <small>{item.state}</small>
            </div>
          </button>
        ))}
      </div>
    </section>
  );
}
