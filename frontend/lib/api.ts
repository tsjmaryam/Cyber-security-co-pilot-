import type {
  CoverageReviewResponse,
  DecisionSupportResponse,
  IncidentContextResponse,
  IncidentListResponse,
  RecordShape,
} from "@/types/api";

const API_BASE_URL = (process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://127.0.0.1:8000").replace(/\/$/, "");

export class ApiError extends Error {
  status?: number;

  constructor(message: string, status?: number) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

async function fetchJson<T>(path: string): Promise<T> {
  const response = await fetch(`${API_BASE_URL}${path}`, {
    headers: { Accept: "application/json" },
    cache: "no-store",
  });

  if (!response.ok) {
    let detail = response.statusText;
    try {
      const payload = (await response.json()) as { detail?: string };
      detail = payload.detail ?? detail;
    } catch {}
    throw new ApiError(detail || "Request failed", response.status);
  }

  return (await response.json()) as T;
}

export async function listIncidents(limit = 25): Promise<RecordShape[]> {
  const response = await fetchJson<IncidentListResponse>(`/incidents?limit=${limit}`);
  return response.incidents;
}

export async function loadIncidentWorkspace(incidentId: string): Promise<{
  incident: RecordShape;
  decisionSupport: RecordShape | null;
  coverageReview: RecordShape | null;
}> {
  const incidentContext = await fetchJson<IncidentContextResponse>(`/incidents/${incidentId}`);

  const [decisionSupportResult, coverageReviewResult] = await Promise.allSettled([
    fetchJson<DecisionSupportResponse>(`/incidents/${incidentId}/decision-support`),
    fetchJson<CoverageReviewResponse>(`/incidents/${incidentId}/coverage-review`),
  ]);

  return {
    incident: incidentContext.incident,
    decisionSupport: decisionSupportResult.status === "fulfilled" ? decisionSupportResult.value.result : null,
    coverageReview: coverageReviewResult.status === "fulfilled" ? coverageReviewResult.value.review : null,
  };
}
