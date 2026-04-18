"use client";

import { useState } from "react";

const queue = [
  { id: "INC-1042", site: "Water Plant East", severity: "High", state: "Needs review" },
  { id: "INC-1038", site: "County Records", severity: "Medium", state: "Monitoring" },
  { id: "INC-1033", site: "City Hospital Annex", severity: "Low", state: "Closed" },
];

const signals = [
  "17 failed sign-in attempts in 3 minutes from an unfamiliar source",
  "The same account moved from sign-in failures into identity lookups",
  "Access-key related activity appeared after the login burst",
];

const timeline = [
  {
    time: "08:41",
    title: "Unusual sign-in activity detected",
    detail: "Sentinel saw repeated failed attempts against a privileged operations account.",
    tone: "critical",
  },
  {
    time: "08:44",
    title: "Behavior changed from login failures to account discovery",
    detail: "The same source began calling identity and account-related APIs.",
    tone: "warning",
  },
  {
    time: "08:47",
    title: "Recommended response prepared for human approval",
    detail: "Sentinel selected the safest immediate step and flagged the remaining uncertainty.",
    tone: "action",
  },
];

const coverage = [
  { label: "Login telemetry", status: "Checked", note: "Suspicious pattern confirmed" },
  { label: "Identity activity", status: "Checked", note: "Privilege-related actions present" },
  { label: "Network telemetry", status: "Missing", note: "Still needed before final containment" },
];

const actions = [
  {
    label: "Temporarily lock access",
    kind: "Recommended",
    detail: "Fastest safe containment step while preserving time for a supervisor review.",
  },
  {
    label: "Escalate to expert",
    kind: "Alternative",
    detail: "Best if this account supports essential services or if downtime risk is high.",
  },
  {
    label: "Collect more evidence",
    kind: "Alternative",
    detail: "Use if the operator needs the missing network branch before approving disruption.",
  },
];

const auditTrail = [
  "08:48 AM — Recommendation created and marked as approval-required.",
  "08:49 AM — Coverage warning added: network telemetry missing.",
  "08:50 AM — Operator opened incident workspace for review.",
];

function StatusPill({
  children,
  tone = "neutral",
}: {
  children: React.ReactNode;
  tone?: "critical" | "warning" | "safe" | "neutral";
}) {
  return <span className={`status-pill status-pill--${tone}`}>{children}</span>;
}

export default function Home() {
  const [selectedView, setSelectedView] = useState<"active" | "audit">("active");

  return (
    <main className="sentinel-shell">
      <div className="sentinel-orb sentinel-orb--left" />
      <div className="sentinel-orb sentinel-orb--right" />

      <div className="app-frame reveal reveal-delay-1">
        <aside className="left-rail">
          <div className="brand-block">
            <p className="eyebrow">Sentinel</p>
            <h1>Operator Console</h1>
            <p>Clear cyber guidance for teams without dedicated security staff.</p>
          </div>

          <nav className="nav-stack">
            <button
              className={`nav-item${selectedView === "active" ? " nav-item--active" : ""}`}
              onClick={() => setSelectedView("active")}
            >
              Active incident
            </button>
            <button
              className={`nav-item${selectedView === "audit" ? " nav-item--active" : ""}`}
              onClick={() => setSelectedView("audit")}
            >
              Audit trail
            </button>
          </nav>

          <section className="queue-panel">
            <div className="rail-heading">
              <span>Incident queue</span>
              <strong>3 open</strong>
            </div>
            <div className="queue-list">
              {queue.map((item, index) => (
                <div className={`queue-item${index === 0 ? " queue-item--active" : ""}`} key={item.id}>
                  <div>
                    <strong>{item.id}</strong>
                    <p>{item.site}</p>
                  </div>
                  <div className="queue-meta">
                    <span>{item.severity}</span>
                    <small>{item.state}</small>
                  </div>
                </div>
              ))}
            </div>
          </section>
        </aside>

        <section className="workspace">
          {selectedView === "active" ? (
            <>
              <header className="topbar">
                <div>
                  <p className="eyebrow">Current incident</p>
                  <h2>INC-1042 • Water Plant East</h2>
                </div>
                <div className="topbar-meta">
                  <StatusPill tone="critical">High severity</StatusPill>
                  <StatusPill tone="warning">Approval required</StatusPill>
                  <StatusPill tone="safe">Audit active</StatusPill>
                </div>
              </header>

              <section className="hero-strip reveal reveal-delay-2">
                <article className="card card--hero-main">
                  <div className="card-heading">
                    <span className="card-kicker">Plain-language summary</span>
                    <StatusPill tone="critical">Live</StatusPill>
                  </div>
                  <h3>Someone may be trying to gain access they should not have.</h3>
                  <p>
                    Sentinel saw a burst of failed sign-ins followed by identity-related activity on a privileged
                    account. This is not a confirmed breach, but it is unusual enough that the operator should review
                    a safe next step now.
                  </p>
                </article>

                <article className="card card--hero-side">
                  <div className="card-heading">
                    <span className="card-kicker">Recommended action</span>
                    <StatusPill tone="warning">Human in the loop</StatusPill>
                  </div>
                  <h3>Temporarily lock access</h3>
                  <p>This is the fastest safe containment step while the missing network context is reviewed.</p>
                  <div className="action-stack">
                    <button className="cta cta--primary">Approve action</button>
                    <button className="cta cta--secondary">Review alternatives</button>
                  </div>
                </article>
              </section>

              <section className="dashboard-grid dashboard-grid--app">
                <article className="card card--primary reveal reveal-delay-2">
                  <div className="card-heading">
                    <span className="card-kicker">Why Sentinel is concerned</span>
                    <StatusPill tone="warning">3 strong signals</StatusPill>
                  </div>
                  <ul className="signal-list">
                    {signals.map((signal) => (
                      <li key={signal}>{signal}</li>
                    ))}
                  </ul>
                </article>

                <article className="card reveal reveal-delay-3">
                  <div className="card-heading">
                    <span className="card-kicker">Confidence</span>
                    <strong className="metric-value">84%</strong>
                  </div>
                  <p className="muted">High enough to recommend action, but not high enough to skip review.</p>
                  <div className="meter">
                    <div className="meter-track" aria-hidden="true">
                      <span className="meter-fill" style={{ width: "84%" }} />
                    </div>
                  </div>
                </article>

                <article className="card reveal reveal-delay-3">
                  <div className="card-heading">
                    <span className="card-kicker">Investigation timeline</span>
                    <StatusPill tone="neutral">Recent</StatusPill>
                  </div>
                  <div className="timeline">
                    {timeline.map((item) => (
                      <div className="timeline-row" key={item.time + item.title}>
                        <div className={`timeline-dot timeline-dot--${item.tone}`} />
                        <div className="timeline-content">
                          <div className="timeline-meta">
                            <span>{item.time}</span>
                            <strong>{item.title}</strong>
                          </div>
                          <p>{item.detail}</p>
                        </div>
                      </div>
                    ))}
                  </div>
                </article>

                <article className="card reveal reveal-delay-4">
                  <div className="card-heading">
                    <span className="card-kicker">Coverage and blind spots</span>
                    <StatusPill tone="warning">1 gap</StatusPill>
                  </div>
                  <div className="check-grid">
                    {coverage.map((check) => (
                      <div className="check-card" key={check.label}>
                        <div className="check-header">
                          <strong>{check.label}</strong>
                          <span>{check.status}</span>
                        </div>
                        <p>{check.note}</p>
                      </div>
                    ))}
                  </div>
                </article>

                <article className="card reveal reveal-delay-4">
                  <div className="card-heading">
                    <span className="card-kicker">Decision workspace</span>
                    <StatusPill tone="safe">Operator review</StatusPill>
                  </div>
                  <div className="decision-list">
                    {actions.map((action) => (
                      <div className="decision-item" key={action.label}>
                        <div>
                          <div className="decision-label-row">
                            <strong>{action.label}</strong>
                            <span>{action.kind}</span>
                          </div>
                          <p>{action.detail}</p>
                        </div>
                        <button className="decision-button">Open</button>
                      </div>
                    ))}
                  </div>
                </article>
              </section>
            </>
          ) : (
            <>
              <header className="topbar">
                <div>
                  <p className="eyebrow">Audit trail</p>
                  <h2>Decision history and system record</h2>
                </div>
                <div className="topbar-meta">
                  <StatusPill tone="neutral">Immutable log</StatusPill>
                  <StatusPill tone="safe">3 entries recorded</StatusPill>
                </div>
              </header>

              <section className="dashboard-grid dashboard-grid--app reveal reveal-delay-2">
                <article className="card card--wide">
                  <div className="card-heading">
                    <span className="card-kicker">Recorded actions</span>
                    <StatusPill tone="neutral">Most recent first</StatusPill>
                  </div>
                  <div className="audit-log-list">
                    {auditTrail.map((entry) => {
                      const [time, detail] = entry.split(" — ");
                      return (
                        <div className="audit-log-item" key={entry}>
                          <div className="audit-log-marker" />
                          <div className="audit-log-content">
                            <strong>{time}</strong>
                            <p>{detail}</p>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </article>
              </section>
            </>
          )}
        </section>
      </div>
    </main>
  );
}
