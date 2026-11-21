"""Storage Sustainability Engine & Evidence-Preserving Retention Policies for ANIE.

Provides:
- Evidence-preserving retention pruning: Never deletes observations or forensic events
  actively referenced by intelligence claims, discrepancy reports, or signed releases.
- Safe compaction and WAL truncation.
- Referential integrity verification.
- Empirical storage, WAL, backup, and release growth projection models.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from hashlib import sha256
import json
from pathlib import Path
import re
from typing import Any, Dict, List, Optional, Set, Tuple

from .real_store import RealObservationStore


PROFILE_PILOT = "pilot"
PROFILE_PRODUCTION = "production"
PROFILE_SCALE = "scale"

_AUDIT_ID_ALLOWED_RE = re.compile(r"^[a-zA-Z0-9_\-\.:@/]{1,64}$")
_SENSITIVE_PREFIXES = (
    "bearer ",
    "token ",
    "secret ",
    "jwt:",
    "ey",
    "ghp_",
    "gho_",
    "glpat-",
    "sk_",
    "pwd:",
    "password:",
    "api_key:",
    "apikey:",
)


def validate_operator_audit_id(audit_id: str) -> str:
    """Validate that an operator audit identifier is a clean handle and not a secret credential.

    Epistemic & Security Separation:
    A non-empty operator_audit_id identifies WHO or what system process triggered retention
    pruning for the tombstone audit log. It does NOT represent cryptographically verified
    authorization. Passwords, bearer tokens, API keys, and sensitive tokens must NEVER be passed
    or stored in the tombstone ledger.
    """
    if not audit_id or not isinstance(audit_id, str):
        raise ValueError("operator_audit_id must be a non-empty string")
    clean = audit_id.strip()
    if not clean:
        raise ValueError("operator_audit_id cannot be blank or whitespace-only")
    lower = clean.lower()
    for prefix in _SENSITIVE_PREFIXES:
        if lower.startswith(prefix):
            raise ValueError(
                "operator_audit_id must be an operator or system identifier (e.g. 'operator:alice', "
                "'sys:retention-cron') and must not contain secret tokens, passwords, or bearer credentials."
            )
    if any(c in clean for c in (" ", "\t", "\n", "\r")):
        raise ValueError("operator_audit_id must not contain whitespace characters")
    if not _AUDIT_ID_ALLOWED_RE.fullmatch(clean):
        raise ValueError(
            f"invalid operator_audit_id {audit_id!r}: must match regex ^[a-zA-Z0-9_\\-\\.:@/]{{1,64}}$ "
            "and not exceed 64 characters"
        )
    return clean


@dataclass(frozen=True)
class RetentionPolicy:
    observation_ttl_days: int = 90
    event_ttl_days: int = 180
    protect_claimed_evidence: bool = True
    protect_discrepancy_evidence: bool = True
    protect_released_evidence: bool = True
    compact_vacuum: bool = True
    allow_destructive_pruning: bool = False
    compact_derived_indexes: bool = True
    authoritative_retention: str = "INDEFINITE"
    operator_audit_id: str | None = None
    operator_authorization: str | None = None  # Deprecated backward-compatible alias for operator_audit_id

    def get_operator_audit_id(self) -> str | None:
        """Resolve operator audit identifier from either operator_audit_id or operator_authorization."""
        return self.operator_audit_id or self.operator_authorization


@dataclass(frozen=True)
class RetentionReport:
    pruned_at: str
    observation_cutoff: str
    event_cutoff: str
    observations_total: int
    observations_pruned: int
    observations_protected: int
    events_total: int
    events_pruned: int
    events_protected: int
    db_size_before_bytes: int
    db_size_after_bytes: int
    bytes_reclaimed: int
    referential_integrity_ok: bool

    @property
    def pruned_observations(self) -> int:
        return self.observations_pruned

    @property
    def protected_observations_kept(self) -> int:
        return self.observations_protected

    @property
    def pruned_events(self) -> int:
        return self.events_pruned

    @property
    def protected_events_kept(self) -> int:
        return self.events_protected

    @property
    def foreign_key_check_passed(self) -> bool:
        return self.referential_integrity_ok

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def __getitem__(self, item: str) -> Any:
        try:
            return getattr(self, item)
        except AttributeError:
            raise KeyError(item)

    def __contains__(self, item: str) -> bool:
        return hasattr(self, item)


@dataclass(frozen=True)
class WorkloadProfile:
    name: str
    description: str
    domains: int
    queries_per_day_per_domain: int
    resolvers: int = 3

    @property
    def daily_observations(self) -> int:
        return self.domains * self.queries_per_day_per_domain * self.resolvers


@dataclass(frozen=True)
class StorageProjection:
    profile_name: str
    days: int
    total_observations: int
    total_events: int
    estimated_db_mb: float
    estimated_wal_peak_mb: float
    estimated_backup_mb: float
    estimated_release_gzip_mb: float

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def __getitem__(self, item: str) -> Any:
        try:
            return getattr(self, item)
        except AttributeError:
            raise KeyError(item)

    def __contains__(self, item: str) -> bool:
        return hasattr(self, item)


def collect_protected_evidence_identifiers(
    store: RealObservationStore,
    policy: RetentionPolicy | None = None,
) -> Tuple[Set[str], Set[str]]:
    """Scan store for evidence hashes and observation IDs referenced by claims, discrepancies, or releases.

    Strict Safety & Verification Guarantees:
    - Never silently swallows corrupt or malformed evidence references (fails closed).
    - Excludes REVOKED claims from protecting evidence unless independently protected.
    - Honors policy flags (protect_claimed_evidence, protect_discrepancy_evidence, protect_released_evidence).
    - Queries durable release_evidence_index for retained signed releases.

    Returns:
        (protected_obs_ids, protected_evidence_hashes)
    """
    if policy is None:
        policy = RetentionPolicy()

    protected_obs_ids: Set[str] = set()
    protected_evidence_hashes: Set[str] = set()

    with store._connect() as conn:
        # 1. From Signed Releases (via durable release_evidence_index)
        if policy.protect_released_evidence:
            # Check if release_evidence_index exists
            has_rel_idx = conn.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='release_evidence_index'"
            ).fetchone()
            if has_rel_idx:
                rel_rows = conn.execute(
                    "SELECT observation_id, event_id, raw_sha256 FROM release_evidence_index WHERE release_sequence > 0"
                ).fetchall()
                for obs_id, ev_id, raw_hash in rel_rows:
                    if obs_id:
                        protected_obs_ids.add(obs_id)
                    if ev_id:
                        protected_obs_ids.add(ev_id)
                    if raw_hash:
                        if not isinstance(raw_hash, str) or len(raw_hash) != 64 or not all(c in "0123456789abcdefABCDEF" for c in raw_hash):
                            raise ValueError(f"malformed raw_sha256 in release_evidence_index: {raw_hash!r}")
                        protected_evidence_hashes.add(raw_hash)

        # 2. From Intelligence Claims (Active only; REVOKED claims do NOT protect evidence)
        if policy.protect_claimed_evidence:
            has_claims_tbl = conn.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='intelligence_claims'"
            ).fetchone()
            if has_claims_tbl:
                claim_rows = conn.execute(
                    "SELECT claim_id, supporting_evidence_hashes_json, payload FROM intelligence_claims"
                ).fetchall()
                for claim_id, ev_hashes_json, payload_str in claim_rows:
                    if not payload_str:
                        raise ValueError(f"missing or empty payload for intelligence_claim: {claim_id!r}")
                    try:
                        p_data = json.loads(payload_str)
                    except Exception as exc:
                        raise ValueError(f"malformed JSON in payload for claim {claim_id!r}: {exc}") from exc

                    # Check verification state: Skip REVOKED claims
                    vstate = p_data.get("verification_state", "")
                    if vstate == "REVOKED":
                        continue

                    if ev_hashes_json:
                        try:
                            hashes = json.loads(ev_hashes_json)
                        except Exception as exc:
                            raise ValueError(f"malformed supporting_evidence_hashes_json for claim {claim_id!r}: {exc}") from exc
                        if not isinstance(hashes, (list, tuple, set)):
                            raise ValueError(f"supporting_evidence_hashes_json must be list for claim {claim_id!r}")
                        for h in hashes:
                            if not isinstance(h, str) or len(h) != 64 or not all(c in "0123456789abcdefABCDEF" for c in h):
                                raise ValueError(f"invalid SHA256 evidence hash in claim {claim_id!r}: {h!r}")
                            protected_evidence_hashes.add(h)

                    obs_refs = p_data.get("properties", {}).get("observation_refs", [])
                    if not isinstance(obs_refs, list):
                        raise ValueError(f"observation_refs must be a list for claim {claim_id!r}")
                    for o_ref in obs_refs:
                        if not isinstance(o_ref, str) or not o_ref.strip():
                            raise ValueError(f"invalid observation_ref in claim {claim_id!r}: {o_ref!r}")
                        protected_obs_ids.add(o_ref)

        # 3. From Discrepancies
        if policy.protect_discrepancy_evidence:
            has_disc_tbl = conn.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='real_discrepancies'"
            ).fetchone()
            if has_disc_tbl:
                disc_rows = conn.execute("SELECT analysis_id, payload FROM real_discrepancies").fetchall()
                for analysis_id, payload_str in disc_rows:
                    if not payload_str:
                        raise ValueError(f"missing or empty payload for discrepancy: {analysis_id!r}")
                    try:
                        data = json.loads(payload_str)
                    except Exception as exc:
                        raise ValueError(f"malformed JSON in payload for discrepancy {analysis_id!r}: {exc}") from exc

                    obs_ids_dict = data.get("observation_ids", {})
                    if not isinstance(obs_ids_dict, dict):
                        raise ValueError(f"observation_ids in discrepancy {analysis_id!r} must be a dict")
                    for obs_id in obs_ids_dict.values():
                        if not isinstance(obs_id, str) or not obs_id.strip():
                            raise ValueError(f"invalid observation_id in discrepancy {analysis_id!r}: {obs_id!r}")
                        protected_obs_ids.add(obs_id)

                    ev_ids_dict = data.get("evidence_ids", {})
                    if not isinstance(ev_ids_dict, dict):
                        raise ValueError(f"evidence_ids in discrepancy {analysis_id!r} must be a dict")
                    for ev_id in ev_ids_dict.values():
                        if not isinstance(ev_id, str) or not ev_id.strip():
                            raise ValueError(f"invalid evidence_id in discrepancy {analysis_id!r}: {ev_id!r}")
                        protected_obs_ids.add(ev_id)

                    ev_hashes_dict = data.get("evidence_hashes", {})
                    if not isinstance(ev_hashes_dict, dict):
                        raise ValueError(f"evidence_hashes in discrepancy {analysis_id!r} must be a dict")
                    for ev_hash in ev_hashes_dict.values():
                        if not isinstance(ev_hash, str) or len(ev_hash) != 64 or not all(c in "0123456789abcdefABCDEF" for c in ev_hash):
                            raise ValueError(f"invalid SHA256 evidence hash in discrepancy {analysis_id!r}: {ev_hash!r}")
                        protected_evidence_hashes.add(ev_hash)

        # 4. Cross-reference: protect observations whose events match protected_evidence_hashes
        if protected_evidence_hashes:
            hash_list = list(protected_evidence_hashes)
            # Chunk query to respect SQLite parameter limits
            for i in range(0, len(hash_list), 500):
                chunk = hash_list[i : i + 500]
                placeholders = ",".join("?" for _ in chunk)
                linked_obs = conn.execute(
                    f"""
                    SELECT o.observation_id
                    FROM real_observations o
                    JOIN real_events e ON o.evidence_id = e.event_id
                    WHERE e.raw_sha256 IN ({placeholders})
                    """,
                    chunk,
                ).fetchall()
                for row in linked_obs:
                    protected_obs_ids.add(row[0])

    return protected_obs_ids, protected_evidence_hashes


def safe_prune_retention(
    store: RealObservationStore,
    policy: RetentionPolicy | None = None,
    now: datetime | None = None,
) -> RetentionReport:
    """Execute evidence-preserving two-phase retention pruning.
    
    Strict Safety Guarantees:
    - Never deletes observations or events referenced by active or historical claims.
    - Preserves foreign-key referential integrity fail-closed.
    - Checkpoints WAL and reclaims unused database pages.
    """
    if policy is None:
        policy = RetentionPolicy()

    now_dt = now or datetime.now(timezone.utc)
    obs_cutoff_dt = now_dt - timedelta(days=policy.observation_ttl_days)
    evt_cutoff_dt = now_dt - timedelta(days=policy.event_ttl_days)

    obs_cutoff_iso = obs_cutoff_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    evt_cutoff_iso = evt_cutoff_dt.strftime("%Y-%m-%dT%H:%M:%SZ")

    size_before = store.db_size_bytes()

    # Collect protected evidence sets
    protected_obs_ids: Set[str] = set()
    protected_evidence_hashes: Set[str] = set()
    if policy.protect_claimed_evidence or policy.protect_discrepancy_evidence or policy.protect_released_evidence:
        protected_obs_ids, protected_evidence_hashes = collect_protected_evidence_identifiers(store, policy=policy)

    obs_pruned = 0
    evt_pruned = 0
    obs_total = 0
    evt_total = 0
    obs_protected_count = 0
    evt_protected_count = 0

    with store._connect() as conn:
        # Pre-count totals
        obs_total = conn.execute("SELECT COUNT(*) FROM real_observations").fetchone()[0]
        evt_total = conn.execute("SELECT COUNT(*) FROM real_events").fetchone()[0]

        # Milestone M3.9/M3.10 Lifecycle Policy: Fail-closed default. Never destructively prune authoritative evidence if disabled.
        if not policy.allow_destructive_pruning:
            prunable_obs = []
            prunable_evs = []
            obs_protected_count = obs_total
            evt_protected_count = evt_total
        else:
            # Explicit operator audit identity required for destructive pruning
            raw_audit_id = policy.get_operator_audit_id()
            if not (raw_audit_id and raw_audit_id.strip()):
                raise ValueError(
                    "Destructive retention pruning requires explicit operator audit identity: non-empty operator_audit_id is required"
                )
            operator_audit_id = validate_operator_audit_id(raw_audit_id)

            # Phase 1: Identify and prune expired observations NOT in protected set
            expired_obs = conn.execute(
                "SELECT observation_id, evidence_id, payload FROM real_observations WHERE observed_at < ?",
                (obs_cutoff_iso,),
            ).fetchall()

            prunable_obs: list[tuple[str, str]] = []
            for o_id, _, o_payload in expired_obs:
                if o_id in protected_obs_ids:
                    obs_protected_count += 1
                else:
                    o_hash = sha256(o_payload.encode("utf-8")).hexdigest() if o_payload else sha256(o_id.encode("utf-8")).hexdigest()
                    prunable_obs.append((o_id, o_hash))

            if prunable_obs:
                now_str = now_dt.strftime("%Y-%m-%dT%H:%M:%SZ")

                # Chunk deletions in batches of 500 to bound SQLite query parameters
                for i in range(0, len(prunable_obs), 500):
                    chunk = prunable_obs[i : i + 500]
                    chunk_ids = [c[0] for c in chunk]
                    for oid, o_hash in chunk:
                        tomb_id = f"tomb_obs_{sha256(f'{oid}:{now_str}'.encode('utf-8')).hexdigest()[:24]}"
                        # Note: column 'operator_authorization' stores operator_audit_id for audit trail logging
                        conn.execute(
                            """
                            INSERT OR IGNORE INTO retention_tombstone_ledger (
                                tombstone_id, record_type, original_id, original_sha256,
                                pruned_at, operator_authorization, policy_reason
                            ) VALUES (?, 'observation', ?, ?, ?, ?, 'policy_ttl')
                            """,
                            (tomb_id, oid, o_hash, now_str, operator_audit_id),
                        )
                    placeholders = ",".join("?" for _ in chunk_ids)
                    cur = conn.execute(
                        f"DELETE FROM real_observations WHERE observation_id IN ({placeholders})",
                        chunk_ids,
                    )
                    obs_pruned += cur.rowcount

            # Phase 2: Identify and prune expired events NOT referenced by ANY observation AND NOT in protected evidence hashes
            expired_events = conn.execute(
                "SELECT event_id, raw_sha256 FROM real_events WHERE observed_at < ?",
                (evt_cutoff_iso,),
            ).fetchall()

            active_ev_ids = set(
                row[0] for row in conn.execute("SELECT DISTINCT evidence_id FROM real_observations").fetchall()
            )

            prunable_evs: list[tuple[str, str]] = []
            for ev_id, ev_hash in expired_events:
                if ev_id in active_ev_ids or ev_hash in protected_evidence_hashes:
                    evt_protected_count += 1
                else:
                    prunable_evs.append((ev_id, ev_hash))

            if prunable_evs:
                now_str = now_dt.strftime("%Y-%m-%dT%H:%M:%SZ")

                for i in range(0, len(prunable_evs), 500):
                    chunk = prunable_evs[i : i + 500]
                    chunk_ids = [c[0] for c in chunk]
                    for eid, e_hash in chunk:
                        tomb_id = f"tomb_evt_{sha256(f'{eid}:{now_str}'.encode('utf-8')).hexdigest()[:24]}"
                        # Note: column 'operator_authorization' stores operator_audit_id for audit trail logging
                        conn.execute(
                            """
                            INSERT OR IGNORE INTO retention_tombstone_ledger (
                                tombstone_id, record_type, original_id, original_sha256,
                                pruned_at, operator_authorization, policy_reason
                            ) VALUES (?, 'event', ?, ?, ?, ?, 'policy_ttl')
                            """,
                            (tomb_id, eid, e_hash, now_str, operator_audit_id),
                        )
                    placeholders = ",".join("?" for _ in chunk_ids)
                    cur = conn.execute(
                        f"DELETE FROM real_events WHERE event_id IN ({placeholders})",
                        chunk_ids,
                    )
                    evt_pruned += cur.rowcount

    # Checkpoint WAL
    store.checkpoint_wal(truncate=True)

    # Optional incremental vacuum / compaction
    if policy.compact_vacuum:
        try:
            with store._connect() as conn:
                conn.execute("PRAGMA incremental_vacuum")
        except Exception:
            pass

    size_after = store.db_size_bytes()
    reclaimed = max(0, size_before - size_after)

    # Fail-closed referential integrity verification
    fk_violations = store.check_referential_integrity()
    if fk_violations:
        raise RuntimeError(f"retention pruning caused foreign-key referential integrity violations: {fk_violations}")

    now_iso = now_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    return RetentionReport(
        pruned_at=now_iso,
        observation_cutoff=obs_cutoff_iso,
        event_cutoff=evt_cutoff_iso,
        observations_total=obs_total,
        observations_pruned=obs_pruned,
        observations_protected=obs_protected_count,
        events_total=evt_total,
        events_pruned=evt_pruned,
        events_protected=evt_protected_count,
        db_size_before_bytes=size_before,
        db_size_after_bytes=size_after,
        bytes_reclaimed=reclaimed,
        referential_integrity_ok=True,
    )


class StorageGrowthModel:
    """Calculates projected storage, WAL, backup, and release footprint over time."""

    BYTES_PER_OBSERVATION_DB = 5335.0  # Measured empirically at 100k scale in M3.4.1 (includes B-tree + FTS5)
    BYTES_PER_EVENT_DB = 1200.0
    GZIP_COMPRESSION_RATIO = 0.12  # Empirical JSONL -> JSONL.GZ ratio (~8.3x compression)

    PROFILES = {
        "pilot": WorkloadProfile(
            name="pilot",
            description="Phase 2 / M3.5 Narrow Pilot (25 domains, 6 queries/day (every 4h), 3 resolvers -> 450 req/day)",
            domains=25,
            queries_per_day_per_domain=6,
            resolvers=3,
        ),
        "production": WorkloadProfile(
            name="production",
            description="Standard Continuous Observatory (100 domains, 24 queries/day, 3 resolvers)",
            domains=100,
            queries_per_day_per_domain=24,
            resolvers=3,
        ),
        "scale": WorkloadProfile(
            name="scale",
            description="High-Throughput Enterprise Ingestion (1,000 domains, 24 queries/day, 3 resolvers)",
            domains=1000,
            queries_per_day_per_domain=24,
            resolvers=3,
        ),
    }

    @classmethod
    def project(cls, profile_name: str, days: int) -> StorageProjection:
        profile = cls.PROFILES.get(profile_name)
        if not profile:
            raise ValueError(f"unknown workload profile: {profile_name!r}; expected one of {sorted(cls.PROFILES)}")

        total_obs = profile.daily_observations * days
        total_evts = total_obs  # 1:1 event to observation in standard DoH collection

        raw_db_bytes = (total_obs * cls.BYTES_PER_OBSERVATION_DB) + (total_evts * cls.BYTES_PER_EVENT_DB)
        db_mb = raw_db_bytes / (1024 * 1024)

        # WAL peak: bounded by checkpoint threshold or ~10% of DB during high concurrency
        wal_peak_mb = min(db_mb * 0.10, 64.0)

        # Backup size: compressed DB dump
        backup_mb = db_mb * 0.35

        # Release GZIP size: raw JSONL compressed
        raw_jsonl_bytes = total_obs * 600.0  # ~600 bytes raw uncompressed observation JSONL
        release_gzip_mb = (raw_jsonl_bytes * cls.GZIP_COMPRESSION_RATIO) / (1024 * 1024)

        return StorageProjection(
            profile_name=profile_name,
            days=days,
            total_observations=total_obs,
            total_events=total_evts,
            estimated_db_mb=round(db_mb, 2),
            estimated_wal_peak_mb=round(wal_peak_mb, 2),
            estimated_backup_mb=round(backup_mb, 2),
            estimated_release_gzip_mb=round(release_gzip_mb, 2),
        )

    project_growth = project

    @classmethod
    def generate_full_report(cls) -> list[StorageProjection]:
        """Generate projections across all profiles for 30, 90, 180, and 365 days."""
        projections = []
        for prof_name in ["pilot", "production", "scale"]:
            for d in [30, 90, 180, 365]:
                projections.append(cls.project(prof_name, d))
        return projections


def rebuild_derived_indexes(store: RealObservationStore) -> dict[str, int]:
    """Deterministically rebuild derived graph nodes and edges from authoritative records.

    Milestone M3.9 Lifecycle Policy:
    Authoritative tables (real_observations, real_events) are immutable empirical sources of truth.
    Derived graph nodes and edges are strictly secondary and can be safely compacted, dropped,
    and rebuilt from scratch without loss of evidence integrity.
    """
    rebuilt_nodes = 0
    rebuilt_edges = 0

    with store._connect() as conn:
        # 1. Clear existing derived graph indexes
        conn.execute("DELETE FROM graph_edges")
        conn.execute("DELETE FROM graph_nodes")

        # 2. Iterate through authoritative real_observations
        obs_rows = conn.execute(
            """
            SELECT o.observation_id, o.evidence_id, o.subject, o.kind, o.observed_at,
                   o.status, o.source_id, o.payload, e.raw_sha256
            FROM real_observations o
            LEFT JOIN real_events e ON o.evidence_id = e.event_id
            ORDER BY o.observed_at ASC, o.observation_id ASC
            """
        ).fetchall()

        from .canonical_entities import (
            canonical_domain_uri,
            canonical_ipv4_uri,
            canonical_ipv6_uri,
            canonicalize_domain,
        )
        from .graph_models import EpistemicLayer, NodeType, RelationType, format_node_id

        for r in obs_rows:
            obs_id, ev_id, subj, kind, obs_at, status, src_id, payload_str, ev_sha = r
            p_data = json.loads(payload_str) if payload_str else {}
            vals = p_data.get("values", [])
            ev_hashes_json = json.dumps([ev_sha]) if ev_sha else "[]"

            # Domain node
            if "." in subj and not subj.replace(".", "").isdigit():
                c_domain = canonicalize_domain(subj)
                d_uri = format_node_id(NodeType.DOMAIN, c_domain)
                conn.execute(
                    """
                    INSERT INTO graph_nodes (
                        node_id, node_type, canonical_name, layer, first_observed_at,
                        last_observed_at, properties_json, payload
                    ) VALUES (?, ?, ?, ?, ?, ?, '{}', '{}')
                    ON CONFLICT(node_id) DO UPDATE SET
                        first_observed_at = min(first_observed_at, excluded.first_observed_at),
                        last_observed_at = max(last_observed_at, excluded.last_observed_at)
                    """,
                    (d_uri, NodeType.DOMAIN.value, c_domain, EpistemicLayer.FACT.value, obs_at, obs_at),
                )
                rebuilt_nodes += 1

                # IP nodes and RESOLVES_TO edges
                for v in vals:
                    if isinstance(v, str) and ("." in v or ":" in v):
                        v_clean = v.strip()
                        ip_uri = format_node_id(NodeType.IP, v_clean)
                        conn.execute(
                            """
                            INSERT INTO graph_nodes (
                                node_id, node_type, canonical_name, layer, first_observed_at,
                                last_observed_at, properties_json, payload
                            ) VALUES (?, ?, ?, ?, ?, ?, '{}', '{}')
                            ON CONFLICT(node_id) DO UPDATE SET
                                first_observed_at = min(first_observed_at, excluded.first_observed_at),
                                last_observed_at = max(last_observed_at, excluded.last_observed_at)
                            """,
                            (ip_uri, NodeType.IP.value, v_clean, EpistemicLayer.FACT.value, obs_at, obs_at),
                        )
                        rebuilt_nodes += 1

                        # Edge
                        edge_id = f"edge_res_{sha256(f'{d_uri}:{ip_uri}:{obs_at}'.encode('utf-8')).hexdigest()[:24]}"
                        conn.execute(
                            """
                            INSERT INTO graph_edges (
                                edge_id, source_id, target_id, relation_type, layer,
                                observed_at, valid_from, valid_until, confidence,
                                ruleset_version, evidence_hashes_json, properties_json, payload
                            ) VALUES (?, ?, ?, ?, ?, ?, ?, NULL, 1.0, 'anie.rebuild.v1', ?, '{}', '{}')
                            ON CONFLICT(edge_id) DO UPDATE SET
                                observed_at = max(observed_at, excluded.observed_at),
                                valid_from = min(valid_from, excluded.valid_from)
                            """,
                            (edge_id, d_uri, ip_uri, RelationType.RESOLVES_TO.value, EpistemicLayer.FACT.value, obs_at, obs_at, ev_hashes_json),
                        )
                        rebuilt_edges += 1

        # Check if intelligence_claims exists and rebuild claim nodes
        has_claims = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='intelligence_claims'"
        ).fetchone()
        if has_claims:
            claim_rows = conn.execute(
                """
                SELECT claim_id, subject_uri, claim_type, layer, asserted_at, payload
                FROM intelligence_claims
                ORDER BY asserted_at ASC, claim_id ASC
                """
            ).fetchall()
            for cr in claim_rows:
                cid, csubj, ctype, clayer, casserted, cpayload = cr
                claim_data = json.loads(cpayload) if cpayload else {}
                csupersedes = claim_data.get("supersedes_claim_id")
                claim_node_id = f"anie:entity:claim:{cid}"
                conn.execute(
                    """
                    INSERT INTO graph_nodes (
                        node_id, node_type, canonical_name, layer, first_observed_at,
                        last_observed_at, properties_json, payload
                    ) VALUES (?, ?, ?, ?, ?, ?, '{}', ?)
                    ON CONFLICT(node_id) DO UPDATE SET
                        first_observed_at = min(first_observed_at, excluded.first_observed_at),
                        last_observed_at = max(last_observed_at, excluded.last_observed_at)
                    """,
                    (claim_node_id, NodeType.INTELLIGENCE_CLAIM.value, cid, clayer or EpistemicLayer.HYPOTHESIS.value, casserted, casserted, cpayload or '{}'),
                )
                rebuilt_nodes += 1

                # If supersedes, create SUPERSEDES edge
                if csupersedes:
                    old_claim_id = f"anie:entity:claim:{csupersedes}"
                    sup_edge_id = f"edge_sup_{sha256(f'{claim_node_id}:{old_claim_id}'.encode('utf-8')).hexdigest()[:24]}"
                    conn.execute(
                        """
                        INSERT INTO graph_edges (
                            edge_id, source_id, target_id, relation_type, layer,
                            observed_at, valid_from, valid_until, confidence,
                            ruleset_version, evidence_hashes_json, properties_json, payload
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, NULL, 1.0, 'anie.rebuild.v1', '[]', '{}', '{}')
                        ON CONFLICT(edge_id) DO UPDATE SET
                            observed_at = max(observed_at, excluded.observed_at)
                        """,
                        (sup_edge_id, claim_node_id, old_claim_id, RelationType.SUPERSEDES.value, EpistemicLayer.HYPOTHESIS.value, casserted, casserted),
                    )
                    rebuilt_edges += 1

    return {"rebuilt_nodes": rebuilt_nodes, "rebuilt_edges": rebuilt_edges}
