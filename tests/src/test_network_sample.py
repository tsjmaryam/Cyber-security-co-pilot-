from __future__ import annotations

from pathlib import Path

from src.network_sample import build_network_evidence_package


def test_build_network_evidence_package_summarizes_sample_rows(tmp_path: Path):
    sample = tmp_path / "network-sample.csv"
    sample.write_text(
        "\n".join(
            [
                "Dst Port,Protocol,Timestamp,Flow Duration,Tot Fwd Pkts,Tot Bwd Pkts,Label",
                "443,6,2025-01-15 14:00:00,120,10,7,Benign",
                "Dst Port,Protocol,Timestamp,Flow Duration,Tot Fwd Pkts,Tot Bwd Pkts,Label",
                "22,6,2025-01-15 14:01:00,900,55,21,Infilteration",
            ]
        ),
        encoding="utf-8",
    )

    evidence = build_network_evidence_package(tmp_path)

    assert evidence is not None
    assert evidence["file_count"] == 1
    assert evidence["total_rows"] == 2
    assert evidence["header_rows_removed"] == 1
    assert evidence["benign_flow_count"] == 1
    assert evidence["suspicious_flow_count"] == 1
    assert evidence["label_counts"]["Infilteration"] == 1
    assert evidence["suspicious_flow_examples"][0]["label"] == "Infilteration"


def test_build_network_evidence_package_returns_none_when_sample_dir_is_empty(tmp_path: Path):
    assert build_network_evidence_package(tmp_path) is None
