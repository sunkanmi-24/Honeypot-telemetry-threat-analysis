"""Analysis pipeline tests (no real traffic involved)."""

from __future__ import annotations

import json

from analyze import records_from_jsonl, to_dataframe


def _write(path, lines):
    with open(path, "w", encoding="utf-8") as handle:
        for line in lines:
            handle.write(line + "\n")


def test_records_from_jsonl_skips_malformed(tmp_path):
    raw = tmp_path / "in.jsonl"
    _write(raw, [
        json.dumps({"event_id": "1", "synthetic": 0, "path": "/admin"}),
        "not-json-at-all",
        "[1, 2, 3]",
        "# comment",
        "",
        json.dumps({"event_id": "2", "synthetic": 1, "path": "/"}),
    ])
    records, stats = records_from_jsonl(str(raw))
    assert len(records) == 2
    assert stats["malformed"] == 1
    assert stats["skipped_non_object"] == 1


def test_to_dataframe_excludes_synthetic(tmp_path):
    records = [
        {"event_id": "1", "synthetic": 1, "path": "/admin",
         "timestamp_utc": "2026-01-01T00:00:00+00:00",
         "classification": "Administrative interface discovery"},
        {"event_id": "2", "synthetic": 0, "path": "/",
         "timestamp_utc": "2026-01-02T00:00:00+00:00",
         "classification": "Normal application request"},
    ]
    frame, quality = to_dataframe(records, include_synthetic=False)
    assert len(frame) == 1
    assert frame.iloc[0]["event_id"] == "2"
    assert quality["synthetic_records"] == 1


def test_to_dataframe_drops_duplicate_events():
    records = [
        {"event_id": "a", "synthetic": 0, "timestamp_utc": "2026-01-01T00:0"
         "0:00+00:00"},
        {"event_id": "a", "synthetic": 0, "timestamp_utc": "2026-01-01T00:0"
         "0:00+00:00"},
    ]
    frame, quality = to_dataframe(records, include_synthetic=False)
    assert len(frame) == 1
    assert quality["duplicate_events_removed"] == 1


def test_to_dataframe_reports_unparseable_timestamps():
    records = [
        {"event_id": "a", "synthetic": 0, "timestamp_utc": "gibberish"},
        {"event_id": "b", "synthetic": 0,
         "timestamp_utc": "2026-01-01T00:00:00+00:00"},
    ]
    frame, quality = to_dataframe(records, include_synthetic=False)
    assert len(frame) == 1
    assert quality["unparseable_timestamps"] == 1


def test_to_dataframe_empty_input():
    frame, quality = to_dataframe([], include_synthetic=False)
    assert frame.empty


def test_run_analysis_empty_dataset_reports_honestly(tmp_path, monkeypatch):
    """The summary must never invent numbers when there is nothing."""
    import analyze
    monkeypatch.setattr(analyze, "TABLE_DIR", str(tmp_path / "tables"))
    monkeypatch.setattr(analyze, "FIGURE_DIR", str(tmp_path / "figures"))
    monkeypatch.setattr(analyze, "SUMMARY_PATH",
                        str(tmp_path / "summary.json"))
    raw = tmp_path / "empty.jsonl"
    raw.write_text("", encoding="utf-8")
    summary = analyze.run_analysis(str(raw), include_synthetic=False)
    assert summary["total_recorded_requests"] == 0
    assert "note_empty" in summary
    assert summary.get("generated_figures", []) == []
