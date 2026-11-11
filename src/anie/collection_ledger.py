"""Append-only SQLite event ledger preserving collection outcome provenance.

Independent of the v0.1 observation store, to avoid changing historical IDs.
The ledger stores normalized metadata, NOT raw provider responses.
"""
from __future__ import annotations

from pathlib import Path
import json
import re
import sqlite3

from .collection_pipeline import CollectionEvent, CollectionRequest
from .observations import Observation, canonical_json

_HEX = re.compile(r"^[0-9a-f]{64}$")


def _validated_event(raw: dict) -> CollectionEvent:
    if not isinstance(raw, dict) or raw.get("schema") != "anie.collection-event.v1":
        raise ValueError("unsupported collection event schema")
    if set(raw) != {"schema", "request", "response_code", "observation", "raw_sha256", "source_id"}:
        raise ValueError("unexpected collection event fields")
    if not isinstance(raw.get("request"), dict) or not isinstance(raw.get("observation"), dict):
        raise ValueError("invalid collection record")
    request_raw = raw["request"]
    if set(request_raw) != {"kind", "subject", "observed_at"}:
        raise ValueError("invalid request fields")
    request = CollectionRequest.create(**request_raw)
    payload = raw["observation"].copy()
    obs_id = payload.pop("observation_id", None)
    observation = Observation.from_dict(payload)
    if observation.observation_id != obs_id or not observation.synthetic:
        raise ValueError("observation provenance mismatch")
    if (observation.kind, observation.subject, observation.observed_at) != (request.kind, request.subject, request.observed_at):
        raise ValueError("observation does not match collection request")
    source = raw.get("source_id")
    if not isinstance(source, str) or not source.startswith("synthetic:") or observation.source_id != source:
        raise ValueError("invalid synthetic source")
    digest = raw.get("raw_sha256")
    if not isinstance(digest, str) or not _HEX.fullmatch(digest):
        raise ValueError("invalid fixture hash")
    code = raw.get("response_code")
    allowed = {"ANSWER", "NXDOMAIN", "NODATA", "SERVFAIL", "REFUSED", "NOTIMP", "FORMERR", "TIMEOUT", "RATE_LIMITED", "UNAVAILABLE", "HTTP_200", "HTTP_404", "HTTP_429", "HTTP_5XX", "HTTP_ERROR", "INVALID_RESPONSE"}
    if code not in allowed:
        raise ValueError("invalid outcome code")
    if (code in {"ANSWER", "HTTP_200"} and observation.status != "ok") or (code in {"NODATA", "NXDOMAIN"} and observation.status != "empty") or (code not in {"ANSWER", "HTTP_200", "NODATA", "NXDOMAIN"} and observation.status != "error"):
        raise ValueError("collection outcome inconsistent with observation")
    result = CollectionEvent(request, code, observation, digest, source)
    if result.to_dict() != raw:
        raise ValueError("collection event is not in canonical form")
    return result


class CollectionLedger:
    """Local offline SQLite ledger; no uploaded telemetry and no network calls."""
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self.path, timeout=10) as db:
            db.execute("""CREATE TABLE IF NOT EXISTS collection_events (
                event_id TEXT PRIMARY KEY,
                subject TEXT NOT NULL,
                observed_at TEXT NOT NULL,
                payload TEXT NOT NULL
            )""")
            db.execute("CREATE INDEX IF NOT EXISTS events_by_subject_time ON collection_events(subject, observed_at, event_id)")

    def add(self, event: CollectionEvent) -> bool:
        validated = _validated_event(event.to_dict())
        with sqlite3.connect(self.path, timeout=10) as db:
            cur = db.execute("INSERT OR IGNORE INTO collection_events (event_id,subject,observed_at,payload) VALUES (?,?,?,?)", (
                validated.event_id, event.request.subject, event.request.observed_at, canonical_json(event.to_dict()),
            ))
            return cur.rowcount == 1

    def by_subject(self, subject: str) -> list[CollectionEvent]:
        with sqlite3.connect(self.path, timeout=10) as db:
            rows = db.execute("SELECT event_id,payload FROM collection_events WHERE subject=? ORDER BY observed_at,event_id LIMIT 10000", (subject,)).fetchall()
        events = []
        for event_id, payload in rows:
            event = _validated_event(json.loads(payload))
            if event.event_id != event_id:
                raise ValueError("ledger row integrity mismatch")
            events.append(event)
        return events
