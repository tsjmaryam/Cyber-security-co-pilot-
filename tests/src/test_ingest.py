from __future__ import annotations

import gzip
import io
import json
import tarfile
from pathlib import Path

from src.ingest import ingest_records, iter_input_sources


def _payload(records: list[object]) -> bytes:
    return json.dumps({"Records": records}).encode("utf-8")


def test_ingest_records_reads_plain_gzip_and_archive_sources(tmp_path: Path):
    plain = tmp_path / "plain.json"
    plain.write_bytes(_payload([{"eventID": "evt-1"}, {"eventID": "evt-2"}]))

    gz_path = tmp_path / "nested.json.gz"
    gz_path.write_bytes(gzip.compress(_payload([{"eventID": "evt-3"}])))

    archive_path = tmp_path / "bundle.tar.gz"
    inner_bytes = gzip.compress(_payload([{"eventID": "evt-4"}]))
    with tarfile.open(archive_path, "w:gz") as archive:
      info = tarfile.TarInfo("inner.json.gz")
      info.size = len(inner_bytes)
      archive.addfile(info, io.BytesIO(inner_bytes))

    discovered = [item.name for item in iter_input_sources(tmp_path)]
    assert discovered == ["bundle.tar.gz", "nested.json.gz", "plain.json"]

    records, metrics = ingest_records(tmp_path)

    assert [item.record["eventID"] for item in records] == ["evt-4", "evt-3", "evt-1", "evt-2"]
    assert metrics.total_files_read == 3
    assert metrics.total_records_parsed == 4
    assert metrics.total_malformed_files == 0
    assert metrics.total_malformed_records == 0


def test_ingest_records_counts_malformed_records_and_files(tmp_path: Path):
    valid = tmp_path / "valid.json"
    valid.write_bytes(_payload([{"eventID": "evt-1"}, "bad-record"]))

    invalid = tmp_path / "invalid.json"
    invalid.write_text('{"notRecords": []}', encoding="utf-8")

    records, metrics = ingest_records(tmp_path)

    assert len(records) == 1
    assert records[0].record["eventID"] == "evt-1"
    assert metrics.total_malformed_records == 1
    assert metrics.malformed_record_reasons == {"NonObjectRecord": 1}
    assert metrics.total_malformed_files == 1
    assert metrics.malformed_file_examples[0]["source"].endswith("invalid.json")

