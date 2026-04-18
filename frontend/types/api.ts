export type RecordShape = Record<string, unknown>;

export interface IncidentListResponse {
  incidents: RecordShape[];
}

export interface IncidentContextResponse {
  incident: RecordShape;
  evidence_package?: RecordShape | null;
  detector_result?: RecordShape | null;
  coverage_assessment?: RecordShape | null;
  decision_support_result?: RecordShape | null;
}

export interface DecisionSupportResponse {
  result: RecordShape;
}

export interface CoverageReviewResponse {
  review: RecordShape;
}
