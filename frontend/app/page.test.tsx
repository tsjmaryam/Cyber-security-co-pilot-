import { fireEvent, render, screen, waitFor } from "@testing-library/react";

import Home from "./page";

vi.mock("next/image", () => ({
  default: (props: Record<string, unknown>) => {
    const { alt, src, priority: _priority, ...rest } = props;
    return <img alt={String(alt ?? "")} src={String(src ?? "")} {...rest} />;
  },
}));

vi.mock("@/lib/api", () => ({
  ApiError: class ApiError extends Error {
    status?: number;
    constructor(message: string, status?: number) {
      super(message);
      this.name = "ApiError";
      this.status = status;
    }
  },
  listIncidents: vi.fn(async () => [
    {
      incident_id: "incident_000000001",
      title: "Unusual login with missing network branch",
      severity_hint: "medium",
      entities: { primary_source_ip_address: "203.0.113.10" },
      start_time: "2026-04-18T09:15:00Z",
      end_time: "2026-04-18T09:22:00Z",
    },
  ]),
  loadIncidentWorkspace: vi.fn(async () => ({
    incident: {
      incident_id: "incident_000000001",
      title: "Unusual login with missing network branch",
      summary: "Summary",
      severity_hint: "medium",
      primary_actor: { actor_key: "demo-user@example.com" },
      entities: { primary_source_ip_address: "203.0.113.10" },
      start_time: "2026-04-18T09:15:00Z",
      end_time: "2026-04-18T09:22:00Z",
      event_sequence: ["ConsoleLogin", "ListUsers", "CreateAccessKey"],
    },
    incidentEvents: [],
    evidencePackage: null,
    detectorResult: {
      risk_score: 0.72,
      risk_band: "medium",
      top_signals: [{ label: "console_login" }],
      model_type: "ebm",
      feature_contributions: [],
    },
    coverageAssessment: {
      completeness_level: "medium",
      checks: [{ category: "network_logs", status: "not_checked", note: "Missing: network logs" }],
      missing_sources: ["network_logs"],
    },
    decisionSupportResult: {
      recommended_action: {
        action_id: "reset_credentials",
        label: "Reset credentials",
        reason: "Contain the account.",
        requires_human_approval: true,
      },
      alternative_actions: [
        {
          action_id: "collect_more_evidence",
          label: "Collect more evidence",
          reason: "Important checks are missing.",
          tradeoff: "This may delay a stronger response.",
        },
      ],
      completeness_assessment: {
        level: "medium",
        warning: "This recommendation may be incomplete.",
        reasons: ["Network telemetry was not checked."],
      },
    },
    decisionSupport: {
      incident_summary: {
        title: "Unusual login with missing network branch",
        summary: "Summary",
        risk_band: "medium",
      },
      recommended_action: {
        action_id: "reset_credentials",
        label: "Reset credentials",
        reason: "Contain the account.",
        requires_human_approval: true,
      },
      alternative_actions: [
        {
          action_id: "collect_more_evidence",
          label: "Collect more evidence",
          reason: "Important checks are missing.",
          tradeoff: "This may delay a stronger response.",
        },
      ],
      completeness_assessment: {
        level: "medium",
        warning: "This recommendation may be incomplete.",
        reasons: ["Network telemetry was not checked."],
      },
    },
    coverageReview: {
      incident_summary: {
        title: "Unusual login with missing network branch",
        summary: "Summary",
        risk_band: "medium",
        top_signals: [{ label: "console_login", detail: "Someone signed in." }],
      },
      recommended_action: {
        action_id: "reset_credentials",
        label: "Reset credentials",
        reason: "Contain the account.",
        requires_human_approval: true,
      },
      alternative_actions: [
        {
          action_id: "collect_more_evidence",
          label: "Collect more evidence",
          reason: "Important checks are missing.",
          tradeoff: "This may delay a stronger response.",
        },
      ],
      recommendation_may_be_incomplete: true,
      decision_risk_note: "Review network evidence before acting.",
      coverage_status_by_category: [
        { category: "network_logs", status: "not_checked", note: "Missing: network logs" },
      ],
      what_could_change_the_decision: ["Network telemetry could change the decision."],
      double_check_candidates: ["Review network logs"],
    },
    operatorHistory: {
      latest_decision: null,
      recent_decisions: [],
      review_events: [],
    },
  })),
  postApprove: vi.fn(),
  getLatestReport: vi.fn(),
  downloadReportPdf: vi.fn(),
  postAlternative: vi.fn(),
  postEscalate: vi.fn(),
  postDoubleCheck: vi.fn(),
  getAgentAuth: vi.fn(async () => ({
    auth_mode: "api_key",
    model: "gpt-5.4",
    labels: { api_key: "Production mode" },
  })),
  postAgentQuery: vi.fn(),
}));

describe("Home page view switching", () => {
  it("switches between simple and expert views and exposes the audit tab only in expert mode", async () => {
    render(<Home />);

    await waitFor(() => {
      expect(screen.getByText(/a\. what happened\?/i)).toBeInTheDocument();
    });
    await waitFor(() => {
      expect(screen.getByText(/reset credentials/i)).toBeInTheDocument();
    });

    expect(screen.queryByRole("button", { name: /audit trail/i })).not.toBeInTheDocument();
    expect(screen.queryByText(/why this incident was flagged/i)).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: /^expert$/i }));

    expect(screen.getByRole("button", { name: /active incident/i })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /audit trail/i })).toBeInTheDocument();
    expect(screen.getByText(/why this incident was flagged/i)).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: /audit trail/i }));
    expect(screen.getByText(/human decision audit trail/i)).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: /^simple$/i }));
    expect(screen.getByText(/a\. what happened\?/i)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /audit trail/i })).not.toBeInTheDocument();
  });
});
