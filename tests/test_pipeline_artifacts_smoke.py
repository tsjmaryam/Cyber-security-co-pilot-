from __future__ import annotations

from pathlib import Path

import pandas as pd
import pytest

from src.cyber_fraudlens_adapter import explain_incident, load_kb, load_model_payload
from src.decision_support_bridge import generate_decision_support_for_incident
from src.weak_label import load_label_rules


PROJECT_ROOT = Path(__file__).resolve().parents[1]
INCIDENTS_PATH = PROJECT_ROOT / "data" / "processed" / "incidents_scored.parquet"
ARTIFACT_PATH = PROJECT_ROOT / "artifacts" / "incident_suspicion_model.joblib"
RULES_PATH = PROJECT_ROOT / "configs" / "incident_label_rules.yaml"


@pytest.mark.skipif(
    not INCIDENTS_PATH.exists() or not ARTIFACT_PATH.exists(),
    reason="Generated incident parquet or trained model artifact is not available.",
)
def test_real_artifact_pipeline_smoke():
    incidents = pd.read_parquet(INCIDENTS_PATH)
    assert incidents.empty is False

    suspicious = incidents.loc[incidents["ml_suspicion_pred"] == 1].sort_values("ml_suspicion_proba", ascending=False)
    assert suspicious.empty is False

    incident_row = suspicious.iloc[[0]]
    incident_id = str(incident_row.iloc[0]["incident_id"])

    model_payload = load_model_payload(ARTIFACT_PATH)
    label_rules = load_label_rules(RULES_PATH)
    kb_df, vectorizer, matrix = load_kb(PROJECT_ROOT)
    explanation = explain_incident(incident_row, model_payload, label_rules, kb_df, vectorizer, matrix)

    assert explanation["incident_id"] == incident_id
    assert explanation["ml_suspicion_pred"] == 1
    assert explanation["ml_suspicion_proba"] >= 0.5
    assert explanation["top_contributors"]

    decision_support = generate_decision_support_for_incident(incident_id, project_root=PROJECT_ROOT)
    assert decision_support["decision_support_result"]["incident_id"] == incident_id
    assert decision_support["validation"]["schema_valid"] is True
    assert decision_support["validation"]["contains_recommended_action"] is True
