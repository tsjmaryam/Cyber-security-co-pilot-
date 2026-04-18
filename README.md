# Cyber-security-co-pilot

CloudTrail normalization pipeline for the flaws.cloud dataset.

## Run

From the project root:

```bash
python -m src.main --project-root .
```

To generate weak suspiciousness labels on incidents and train the baseline incident model:

```bash
python -m src.train_model --project-root .
```

Default config lives in `configs/pipeline_config.yaml` and behavioral flag rules live in `configs/event_flag_rules.yaml`.

## Outputs

- `data/processed/events_flat.parquet`
- `data/processed/events_flat.csv`
- `data/processed/events_flat/` partitioned by `event_date`
- `data/processed/incidents.parquet`
- `data/processed/incidents/` partitioned by `incident_start_date`
- `reports/data_quality_report.json`
- `reports/schema.json`
- `reports/feature_dictionary.md`
- `data/processed/incidents_labeled.parquet`
- `data/processed/incidents_scored.parquet`
- `reports/incident_label_report.json`
- `reports/incident_model_report.json`
- `artifacts/incident_suspicion_model.joblib`

## Structure

- `src/ingest.py`: scans input files and tar archives, parses CloudTrail payloads, and preserves provenance
- `src/normalize.py`: flattens CloudTrail records into a canonical event table
- `src/derive_features.py`: adds ordering keys, convenience flags, missingness states, and rolling counts
- `src/build_incidents.py`: groups ordered events into inactivity-bounded incidents
- `src/validate.py`: builds schema metadata and validation summaries
- `src/export.py`: writes parquet, CSV, and report artifacts
- `src/weak_label.py`: assigns rule-based weak suspiciousness labels to incidents
- `src/train_model.py`: trains and scores the baseline incident suspicion model
- `notebooks/sanity_checks.ipynb`: starter notebook for quick inspection
