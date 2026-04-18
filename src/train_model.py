from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.impute import SimpleImputer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score, classification_report, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler
from sklearn.preprocessing import FunctionTransformer

from .logging_utils import configure_logging, get_logger
from .weak_label import apply_weak_labels, load_label_rules


NUMERIC_FEATURES = [
    "incident_duration_seconds",
    "event_count",
    "distinct_event_names",
    "distinct_event_sources",
    "distinct_regions",
    "error_event_count",
    "success_event_count",
    "failure_ratio",
    "events_per_minute",
]

BOOLEAN_FEATURES = [
    "contains_console_login",
    "contains_recon_like_api",
    "contains_privilege_change_api",
    "contains_resource_creation_api",
    "actor_is_root",
    "actor_is_assumed_role",
    "has_high_failure_ratio",
    "has_failure_burst",
    "has_event_burst",
    "has_broad_surface_area",
    "has_iam_sequence",
    "has_sts_sequence",
    "has_ec2_sequence",
    "has_recon_plus_privilege",
    "has_recon_plus_resource_creation",
    "has_privilege_plus_resource_creation",
    "has_root_plus_privilege",
]

CATEGORICAL_FEATURES = [
    "actor_key",
    "primary_source_ip_address",
    "first_event_name",
    "last_event_name",
    "top_event_name",
]

logger = get_logger(__name__)


def _boolean_to_float(values):
    return values.astype(float)


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate weak labels for incidents and train a baseline suspicion model.")
    parser.add_argument("--project-root", default=".", help="Project root containing configs/, data/, and reports/.")
    parser.add_argument(
        "--input-incidents",
        default="data/processed/incidents.parquet",
        help="Incident parquet path relative to project root.",
    )
    parser.add_argument(
        "--label-rules",
        default="configs/incident_label_rules.yaml",
        help="Weak-label rule config relative to project root.",
    )
    parser.add_argument("--artifacts-dir", default="artifacts", help="Artifact output directory relative to project root.")
    args = parser.parse_args()

    configure_logging()
    project_root = Path(args.project_root).resolve()
    logger.info("Starting training run project_root=%s input=%s", project_root, args.input_incidents)
    incidents = pd.read_parquet(project_root / args.input_incidents)
    rules = load_label_rules(project_root / args.label_rules)
    labeled, label_report = apply_weak_labels(incidents, rules)
    logger.info("Weak labeling complete incidents=%s positives=%s", len(labeled), int(labeled["weak_label_suspicious"].sum()))

    processed_root = project_root / "data" / "processed"
    reports_root = project_root / "reports"
    artifacts_root = project_root / args.artifacts_dir
    processed_root.mkdir(parents=True, exist_ok=True)
    reports_root.mkdir(parents=True, exist_ok=True)
    artifacts_root.mkdir(parents=True, exist_ok=True)

    labeled.to_parquet(processed_root / "incidents_labeled.parquet", index=False)
    labeled.head(100000).to_csv(processed_root / "incidents_labeled_sample.csv", index=False)
    (reports_root / "incident_label_report.json").write_text(json.dumps(label_report, indent=2), encoding="utf-8")

    model_report, scored = train_incident_model(labeled, artifacts_root / "incident_suspicion_model.joblib")
    logger.info("Model training complete scored_rows=%s artifact=%s", len(scored), artifacts_root / "incident_suspicion_model.joblib")
    scored.to_parquet(processed_root / "incidents_scored.parquet", index=False)
    scored.head(100000).to_csv(processed_root / "incidents_scored_sample.csv", index=False)
    (reports_root / "incident_model_report.json").write_text(json.dumps(model_report, indent=2), encoding="utf-8")
    print(
        {
            "incidents": int(len(labeled)),
            "positives": int(labeled["weak_label_suspicious"].sum()),
            "artifact": str(artifacts_root / "incident_suspicion_model.joblib"),
        }
    )
    return 0


def train_incident_model(labeled: pd.DataFrame, artifact_path: Path) -> tuple[dict[str, Any], pd.DataFrame]:
    logger.info("Preparing training matrix rows=%s", len(labeled))
    X = labeled[NUMERIC_FEATURES + BOOLEAN_FEATURES + CATEGORICAL_FEATURES].copy()
    y = labeled["weak_label_suspicious"].astype(int)

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.2,
        random_state=42,
        stratify=y if y.nunique() > 1 else None,
    )
    logger.info("Split train_rows=%s test_rows=%s positive_rate=%.4f", len(X_train), len(X_test), float(y.mean()))

    numeric_transformer = Pipeline(
        steps=[
            ("imputer", SimpleImputer(strategy="constant", fill_value=0.0)),
            ("scaler", StandardScaler()),
        ]
    )
    boolean_transformer = Pipeline(
        steps=[
            (
                "cast",
                FunctionTransformer(
                    _boolean_to_float,
                    feature_names_out="one-to-one",
                ),
            ),
            ("imputer", SimpleImputer(strategy="constant", fill_value=0.0)),
        ]
    )
    categorical_transformer = Pipeline(
        steps=[
            ("imputer", SimpleImputer(strategy="constant", fill_value="UNKNOWN")),
            ("onehot", OneHotEncoder(handle_unknown="ignore", min_frequency=10)),
        ]
    )

    preprocessor = ColumnTransformer(
        transformers=[
            ("num", numeric_transformer, NUMERIC_FEATURES),
            ("bool", boolean_transformer, BOOLEAN_FEATURES),
            ("cat", categorical_transformer, CATEGORICAL_FEATURES),
        ]
    )

    model = Pipeline(
        steps=[
            ("preprocessor", preprocessor),
            (
                "classifier",
                LogisticRegression(max_iter=4000, class_weight="balanced", solver="saga"),
            ),
        ]
    )
    model.fit(X_train, y_train)
    logger.info("Baseline model fit complete")

    train_proba = model.predict_proba(X_train)[:, 1]
    test_proba = model.predict_proba(X_test)[:, 1]
    test_pred = (test_proba >= 0.5).astype(int)
    scored_all = labeled.copy()
    scored_all["ml_suspicion_proba"] = model.predict_proba(X)[:, 1]
    scored_all["ml_suspicion_pred"] = (scored_all["ml_suspicion_proba"] >= 0.5).astype(int)

    model_payload = {
        "model": model,
        "feature_columns": NUMERIC_FEATURES + BOOLEAN_FEATURES + CATEGORICAL_FEATURES,
        "label_column": "weak_label_suspicious",
    }
    joblib.dump(model_payload, artifact_path)
    logger.info("Model artifact written path=%s", artifact_path)

    top_coefficients = extract_top_coefficients(model, top_n=25)
    report = {
        "note": "Metrics are measured against rule-derived weak labels, not analyst-confirmed malicious ground truth.",
        "train_rows": int(len(X_train)),
        "test_rows": int(len(X_test)),
        "positive_rate_train": round(float(y_train.mean()), 6),
        "positive_rate_test": round(float(y_test.mean()), 6),
        "roc_auc_test": _safe_metric(lambda: roc_auc_score(y_test, test_proba)),
        "average_precision_test": _safe_metric(lambda: average_precision_score(y_test, test_proba)),
        "classification_report": classification_report(y_test, test_pred, output_dict=True),
        "top_positive_coefficients": top_coefficients["positive"],
        "top_negative_coefficients": top_coefficients["negative"],
    }
    logger.debug("Model metrics roc_auc_test=%s average_precision_test=%s", report["roc_auc_test"], report["average_precision_test"])
    return _jsonable(report), scored_all


def extract_top_coefficients(model: Pipeline, top_n: int = 25) -> dict[str, list[dict[str, Any]]]:
    classifier = model.named_steps["classifier"]
    preprocessor = model.named_steps["preprocessor"]
    feature_names = list(preprocessor.get_feature_names_out())
    coefficients = classifier.coef_[0]
    pairs = sorted(zip(feature_names, coefficients), key=lambda item: item[1], reverse=True)
    positive = [{"feature": name, "coefficient": round(float(value), 6)} for name, value in pairs[:top_n]]
    negative = [
        {"feature": name, "coefficient": round(float(value), 6)}
        for name, value in sorted(zip(feature_names, coefficients), key=lambda item: item[1])[:top_n]
    ]
    return {"positive": positive, "negative": negative}


def _jsonable(value: Any) -> Any:
    if hasattr(value, "item") and callable(value.item):
        try:
            return value.item()
        except Exception:
            pass
    if isinstance(value, dict):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_jsonable(item) for item in value]
    if isinstance(value, float):
        return round(value, 6)
    if isinstance(value, (pd.Timestamp,)):
        return value.isoformat()
    if value is pd.NA or (isinstance(value, float) and np.isnan(value)):
        return None
    return value


def _safe_metric(metric_fn) -> float | None:
    try:
        return round(float(metric_fn()), 6)
    except Exception:
        return None


if __name__ == "__main__":
    raise SystemExit(main())
