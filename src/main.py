from __future__ import annotations

import argparse
from pathlib import Path

import yaml

from .build_incidents import build_incidents
from .derive_features import derive_event_features, load_flag_rules
from .export import ensure_output_structure, write_outputs
from .ingest import ingest_records
from .normalize import normalize_records
from .validate import build_data_quality_report, build_schema_definition, validate_outputs


def main() -> int:
    parser = argparse.ArgumentParser(description="Build normalized CloudTrail event and incident tables.")
    parser.add_argument("--project-root", default=".", help="Project root containing configs/, data/, and reports/.")
    parser.add_argument("--config", default="configs/pipeline_config.yaml", help="Pipeline config path relative to project root.")
    parser.add_argument("--flag-rules", default="configs/event_flag_rules.yaml", help="Flag rule config path relative to project root.")
    args = parser.parse_args()

    project_root = Path(args.project_root).resolve()
    config = _load_yaml(project_root / args.config)
    flag_rules = load_flag_rules(project_root / args.flag_rules)

    ensure_output_structure(project_root)
    raw_records, ingest_metrics = ingest_records(project_root / config["input_path"])
    events = derive_event_features(normalize_records(raw_records), flag_rules)
    incidents = build_incidents(
        events,
        incident_gap_minutes=int(config["incident_gap_minutes"]),
        ordered_sequence_limit=int(config["ordered_sequence_limit"]),
    )
    quality_report = build_data_quality_report(events, incidents, ingest_metrics)
    schema_definition = build_schema_definition(events, incidents)
    validation_errors = validate_outputs(events, incidents, ingest_metrics)
    quality_report["validation_errors"] = validation_errors

    write_outputs(
        events=events,
        incidents=incidents,
        schema_definition=schema_definition,
        data_quality_report=quality_report,
        output_root=project_root / config["output_root"],
        reports_root=project_root / config["reports_root"],
        csv_sample_limit=int(config["csv_sample_limit"]),
        write_csv_sample=bool(config["write_csv_sample"]),
        write_full_csv=bool(config["write_full_csv"]),
    )
    print({"events": int(len(events)), "incidents": int(len(incidents)), "validation_errors": len(validation_errors)})
    return 1 if validation_errors else 0


def _load_yaml(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as handle:
        return yaml.safe_load(handle) or {}


if __name__ == "__main__":
    raise SystemExit(main())
