from __future__ import annotations

import gzip
import json
import tarfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Generator, Iterable


SUPPORTED_SUFFIXES = (".json", ".json.gz", ".gz")
SUPPORTED_ARCHIVES = (".tar", ".tar.gz", ".tgz")


@dataclass(slots=True)
class RawRecord:
    source_file_path: str
    source_file_name: str
    record_index_in_file: int
    ingest_ts_utc: datetime
    record: dict


@dataclass(slots=True)
class IngestMetrics:
    total_files_read: int = 0
    total_records_parsed: int = 0
    total_malformed_files: int = 0
    total_malformed_records: int = 0
    malformed_file_examples: list | None = None
    malformed_record_reasons: dict | None = None

    def __post_init__(self) -> None:
        self.malformed_file_examples = []
        self.malformed_record_reasons = {}

    def add_file_error(self, source: str, reason: str) -> None:
        self.total_malformed_files += 1
        self.malformed_file_examples.append({"source": source, "reason": reason})

    def add_record_error(self, reason: str) -> None:
        self.total_malformed_records += 1
        self.malformed_record_reasons[reason] = self.malformed_record_reasons.get(reason, 0) + 1


def iter_input_sources(input_path: Path) -> Iterable[Path]:
    if input_path.is_file():
        yield input_path
        return
    for path in sorted(input_path.rglob("*")):
        if path.is_file() and _is_supported_path(path):
            yield path


def ingest_records(input_path: str | Path) -> tuple[list[RawRecord], IngestMetrics]:
    path = Path(input_path)
    metrics = IngestMetrics()
    records: list[RawRecord] = []
    for source_path in iter_input_sources(path):
        try:
            for item in _read_source(source_path, metrics):
                records.append(item)
                metrics.total_records_parsed += 1
        except Exception as exc:  # pragma: no cover
            metrics.add_file_error(str(source_path), type(exc).__name__)
    return records, metrics


def _read_source(source_path: Path, metrics: IngestMetrics) -> Generator[RawRecord, None, None]:
    if _is_archive_path(source_path):
        yield from _read_archive(source_path, metrics)
        return
    metrics.total_files_read += 1
    yield from _read_cloudtrail_file(
        source_label=str(source_path),
        source_file_name=source_path.name,
        raw_bytes=source_path.read_bytes(),
        metrics=metrics,
    )


def _read_archive(source_path: Path, metrics: IngestMetrics) -> Generator[RawRecord, None, None]:
    mode = "r:gz" if str(source_path).endswith((".tar.gz", ".tgz")) else "r"
    with tarfile.open(source_path, mode) as archive:
        for member in archive.getmembers():
            if not member.isfile() or not _is_supported_name(member.name):
                continue
            try:
                metrics.total_files_read += 1
                extracted = archive.extractfile(member)
                if extracted is None:
                    metrics.add_file_error(f"{source_path}::{member.name}", "EmptyArchiveMember")
                    continue
                yield from _read_cloudtrail_file(
                    source_label=f"{source_path}::{member.name}",
                    source_file_name=Path(member.name).name,
                    raw_bytes=extracted.read(),
                    metrics=metrics,
                )
            except Exception as exc:
                metrics.add_file_error(f"{source_path}::{member.name}", type(exc).__name__)


def _read_cloudtrail_file(
    source_label: str,
    source_file_name: str,
    raw_bytes: bytes,
    metrics: IngestMetrics,
) -> Generator[RawRecord, None, None]:
    decoded_bytes = gzip.decompress(raw_bytes) if source_file_name.endswith(".gz") else raw_bytes
    payload = json.loads(decoded_bytes.decode("utf-8"))
    if not isinstance(payload, dict) or "Records" not in payload or not isinstance(payload["Records"], list):
        raise ValueError("MissingRecordsArray")
    ingest_ts = datetime.now(timezone.utc)
    for record_index, record in enumerate(payload["Records"]):
        if not isinstance(record, dict):
            metrics.add_record_error("NonObjectRecord")
            continue
        yield RawRecord(
            source_file_path=source_label,
            source_file_name=source_file_name,
            record_index_in_file=record_index,
            ingest_ts_utc=ingest_ts,
            record=record,
        )


def _is_supported_path(path: Path) -> bool:
    return _is_supported_name(path.name.lower())


def _is_supported_name(name: str) -> bool:
    return name.endswith(SUPPORTED_SUFFIXES + SUPPORTED_ARCHIVES)


def _is_archive_path(path: Path) -> bool:
    return path.name.lower().endswith(SUPPORTED_ARCHIVES)
