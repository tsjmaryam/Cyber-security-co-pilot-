import type { RecordShape } from "@/types/api";

function asRecord(value: unknown): RecordShape {
  return value && typeof value === "object" && !Array.isArray(value) ? (value as RecordShape) : {};
}

function asArray<T = unknown>(value: unknown): T[] {
  return Array.isArray(value) ? (value as T[]) : [];
}

function asString(value: unknown, fallback = "Unavailable"): string {
  return typeof value === "string" && value.trim() ? value : fallback;
}

export function ReportModal({
  open,
  loading,
  report,
  error,
  onClose,
  onPrint,
}: {
  open: boolean;
  loading: boolean;
  report: RecordShape | null;
  error: string | null;
  onClose: () => void;
  onPrint: () => void;
}) {
  if (!open) return null;

  const reportRecord = asRecord(report);
  const approvedAction = asRecord(reportRecord.approved_action);
  const concerns = asArray<string>(reportRecord.why_sentinel_is_concerned);
  const blindSpots = asArray<string>(reportRecord.blind_spots);

  return (
    <div className="report-modal-backdrop" role="presentation">
      <div aria-modal="true" className="report-modal" role="dialog">
        <div className="report-modal__header">
          <div>
            <span className="card-kicker">Approval report</span>
            <h3>{loading ? "Generating report" : "Report drafted"}</h3>
          </div>
          <button className="report-modal__close" onClick={onClose} type="button">
            Close
          </button>
        </div>

        {loading ? (
          <div className="report-modal__loading">
            <div className="report-spinner" aria-hidden="true" />
            <p>Sentinel is drafting a one-page summary from the incident context and your rationale.</p>
          </div>
        ) : error ? (
          <div className="warning-banner">
            <strong>Report generation failed.</strong>
            <span>{error}</span>
          </div>
        ) : (
          <div className="report-preview">
            <div className="report-preview__meta">
              <span>Issue #{asString(reportRecord.incident_id, "incident")}</span>
              <span>{asString(reportRecord.severity, "Unknown")} priority</span>
              <span>{asString(reportRecord.generated_at, "Recently")}</span>
            </div>

            <section className="report-section">
              <h4>{asString(reportRecord.title, "Incident report")}</h4>
              <p>{asString(reportRecord.summary, "Summary unavailable.")}</p>
            </section>

            <section className="report-section">
              <h5>Approved action</h5>
              <p><strong>{asString(approvedAction.label, "Approved action")}</strong></p>
              <p>{asString(approvedAction.reason, "No action reason available.")}</p>
            </section>

            <section className="report-section">
              <h5>Why the action was taken</h5>
              <p>{asString(reportRecord.operator_rationale, "No operator rationale was provided.")}</p>
            </section>

            <section className="report-section">
              <h5>Why Sentinel was concerned</h5>
              <ul>
                {concerns.map((item) => (
                  <li key={item}>{item}</li>
                ))}
              </ul>
            </section>

            <section className="report-section">
              <h5>Known blind spots</h5>
              <ul>
                {blindSpots.map((item) => (
                  <li key={item}>{item}</li>
                ))}
              </ul>
            </section>

            <div className="report-modal__actions">
              <button className="cta cta--secondary" onClick={onClose} type="button">
                Close
              </button>
              <button className="cta cta--primary" onClick={onPrint} type="button">
                Turn into PDF
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
