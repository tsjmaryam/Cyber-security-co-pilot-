from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any

import pandas as pd

from .logging_utils import get_logger

logger = get_logger(__name__)


NETWORK_SAMPLE_COLUMNS = [
    "Timestamp",
    "Dst Port",
    "Protocol",
    "Flow Duration",
    "Tot Fwd Pkts",
    "Tot Bwd Pkts",
    "Label",
]


def build_network_evidence_package(
    sample_dir: str | Path,
    *,
    max_example_flows: int = 6,
) -> dict[str, Any] | None:
    sample_path = Path(sample_dir)
    csv_paths = sorted(sample_path.glob("*.csv"))
    if not csv_paths:
        logger.info("No network sample files found sample_dir=%s", sample_path)
        return None

    label_counts: Counter[str] = Counter()
    file_summaries: list[dict[str, Any]] = []
    suspicious_examples: list[dict[str, Any]] = []
    total_rows = 0
    header_rows_removed = 0

    for csv_path in csv_paths:
        logger.info("Reading network sample path=%s", csv_path)
        frame = pd.read_csv(
            csv_path,
            usecols=lambda column: column in NETWORK_SAMPLE_COLUMNS,
            low_memory=False,
        )
        frame["Label"] = frame["Label"].astype(str).str.strip()
        repeated_header_rows = int((frame["Label"] == "Label").sum())
        header_rows_removed += repeated_header_rows
        frame = frame.loc[frame["Label"] != "Label"].copy()
        total_rows += len(frame)

        counts = frame["Label"].value_counts().to_dict()
        label_counts.update({str(label): int(count) for label, count in counts.items()})
        file_summaries.append(
            {
                "file_name": csv_path.name,
                "row_count": int(len(frame)),
                "label_counts": {str(label): int(count) for label, count in counts.items()},
            }
        )

        suspicious_rows = frame.loc[frame["Label"].str.lower() != "benign"]
        if suspicious_rows.empty:
            continue
        remaining_slots = max_example_flows - len(suspicious_examples)
        if remaining_slots <= 0:
            continue
        suspicious_examples.extend(
            suspicious_rows.head(remaining_slots)
            .rename(
                columns={
                    "Timestamp": "timestamp",
                    "Dst Port": "dst_port",
                    "Protocol": "protocol",
                    "Flow Duration": "flow_duration",
                    "Tot Fwd Pkts": "tot_fwd_pkts",
                    "Tot Bwd Pkts": "tot_bwd_pkts",
                    "Label": "label",
                }
            )
            .to_dict(orient="records")
        )

    benign_count = int(label_counts.get("Benign", 0))
    suspicious_flow_count = max(total_rows - benign_count, 0)
    suspicious_ratio = round((suspicious_flow_count / total_rows), 4) if total_rows else 0.0
    top_suspicious_labels = [
        {"label": label, "count": int(count)}
        for label, count in label_counts.most_common()
        if label.lower() != "benign"
    ]

    evidence = {
        "dataset": "CSE-CIC-IDS2018 sample",
        "sample_dir": str(sample_path),
        "file_count": len(csv_paths),
        "total_rows": int(total_rows),
        "header_rows_removed": int(header_rows_removed),
        "benign_flow_count": benign_count,
        "suspicious_flow_count": suspicious_flow_count,
        "suspicious_ratio": suspicious_ratio,
        "label_counts": {label: int(count) for label, count in label_counts.items()},
        "top_suspicious_labels": top_suspicious_labels,
        "files": file_summaries,
        "suspicious_flow_examples": suspicious_examples,
    }
    logger.info(
        "Built network evidence package files=%s total_rows=%s suspicious_flows=%s",
        evidence["file_count"],
        evidence["total_rows"],
        evidence["suspicious_flow_count"],
    )
    return evidence
