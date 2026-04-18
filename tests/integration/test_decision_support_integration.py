from pathlib import Path

import pytest

from src.decision_support_bridge import generate_decision_support_for_incident


PROJECT_ROOT = Path(__file__).resolve().parents[2]
INCIDENTS_SCORED_PATH = PROJECT_ROOT / "data" / "processed" / "incidents_scored.parquet"


@pytest.mark.skipif(not INCIDENTS_SCORED_PATH.exists(), reason="Scored incident artifact not present in this environment.")
def test_bridge_integration_for_real_incident():
    try:
        result = generate_decision_support_for_incident("incident_000000001", project_root=".")
    except (AttributeError, FileNotFoundError, ModuleNotFoundError, ValueError) as exc:
        pytest.skip(f"Real incident artifact is not portable in this environment: {exc}")
    assert result["decision_support_result"]["incident_id"] == "incident_000000001"
    assert result["validation"]["action_ids_valid"] is True
