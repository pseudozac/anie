"""Capacity Acquisition & Bounded Automated Retry Engine for Oracle Ampere A1 (Phase 3.5).

Implements bounded, idempotent, fail-closed automated retries for acquiring Always Free
ARM64 capacity (VM.Standard.A1.Flex: 2 OCPUs, 12 GB RAM, 50 GB boot volume) in OCI:
- Minimum 60-minute interval between attempts (never more frequent than once per hour).
- Exponential backoff for throttling or unexpected API failures.
- Mutual exclusion locking to guarantee zero parallel provisioning attempts.
- Idempotency verification preventing duplicate instance creation.
- Strict 7-day (168-hour) expiration boundary.
- Immediate termination of retries upon successful provisioning.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import sys
import time
from typing import Any, Dict, List, Optional, Tuple

STATE_PENDING = "PENDING"
STATE_RETRYING = "RETRYING"
STATE_ACQUIRED = "ACQUIRED"
STATE_EXPIRED = "EXPIRED"
STATE_THROTTLED = "THROTTLED"
STATE_FAILED = "FAILED"

OUTCOME_OUT_OF_CAPACITY = "OUT_OF_CAPACITY"
OUTCOME_SUCCESS = "SUCCESS"
OUTCOME_THROTTLED = "THROTTLED"
OUTCOME_API_ERROR = "API_ERROR"


@dataclass(frozen=True)
class CapacityAcquisitionConfig:
    instance_name: str = "anie-arm-01"
    shape: str = "VM.Standard.A1.Flex"
    ocpus: int = 2
    memory_in_gbs: int = 12
    boot_volume_gbs: int = 50
    os_image: str = "Oracle Linux 9 (aarch64)"
    region: str = "ap-hyderabad-1"
    availability_domain: str = "AD-1"
    compartment_name: str = "anie"
    vcn_name: str = "anie-vcn"
    subnet_name: str = "public subnet-anie-vcn"
    assign_public_ip: bool = True
    min_interval_seconds: int = 3600  # 60 minutes minimum between attempts
    max_duration_seconds: int = 7 * 86400  # 7 days max lifetime
    initial_backoff_seconds: int = 3600
    max_backoff_seconds: int = 28800  # 8 hours maximum backoff cap
    backoff_multiplier: float = 2.0


@dataclass
class CapacityAcquisitionState:
    status: str
    started_at: str
    expires_at: str
    total_attempts: int = 0
    consecutive_out_of_capacity: int = 0
    consecutive_api_errors: int = 0
    last_attempt_at: str | None = None
    next_eligible_at: str | None = None
    last_outcome: str | None = None
    last_error_message: str | None = None
    acquired_instance_ocid: str | None = None
    acquired_public_ip: str | None = None
    acquired_private_ip: str | None = None
    acquired_at: str | None = None
    attempt_history: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CapacityAcquisitionState:
        return cls(
            status=data.get("status", STATE_PENDING),
            started_at=data["started_at"],
            expires_at=data["expires_at"],
            total_attempts=data.get("total_attempts", 0),
            consecutive_out_of_capacity=data.get("consecutive_out_of_capacity", 0),
            consecutive_api_errors=data.get("consecutive_api_errors", 0),
            last_attempt_at=data.get("last_attempt_at"),
            next_eligible_at=data.get("next_eligible_at"),
            last_outcome=data.get("last_outcome"),
            last_error_message=data.get("last_error_message"),
            acquired_instance_ocid=data.get("acquired_instance_ocid"),
            acquired_public_ip=data.get("acquired_public_ip"),
            acquired_private_ip=data.get("acquired_private_ip"),
            acquired_at=data.get("acquired_at"),
            attempt_history=data.get("attempt_history", []),
        )


class CrossPlatformLock:
    """Robust OS-level file lock ensuring mutual exclusion against concurrent provisioning attempts."""

    def __init__(self, lock_file_path: Path):
        self.lock_file_path = Path(lock_file_path)
        self.fd: Any = None

    def acquire(self) -> bool:
        self.lock_file_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            self.fd = open(self.lock_file_path, "a+")
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(self.fd.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(self.fd.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            return True
        except (IOError, OSError):
            if self.fd:
                try:
                    self.fd.close()
                except Exception:
                    pass
                self.fd = None
            return False

    def release(self):
        if self.fd:
            try:
                if os.name == "nt":
                    import msvcrt
                    self.fd.seek(0)
                    msvcrt.locking(self.fd.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(self.fd.fileno(), fcntl.LOCK_UN)
                self.fd.close()
            except Exception:
                pass
            finally:
                self.fd = None


class CapacityAcquisitionManager:
    """Manages the lifecycle, rate-limiting, and idempotency of Ampere A1 capacity acquisition."""

    def __init__(
        self,
        state_dir: str | Path,
        config: CapacityAcquisitionConfig | None = None,
        now: datetime | None = None,
    ):
        self.state_dir = Path(state_dir)
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.config = config or CapacityAcquisitionConfig()
        self.state_file = self.state_dir / "capacity_acquisition_state.json"
        self.lock = CrossPlatformLock(self.state_dir / "capacity_acquisition.lock")
        self.state = self._load_or_initialize_state(now)

    def _load_or_initialize_state(self, now: datetime | None = None) -> CapacityAcquisitionState:
        now_dt = now or datetime.now(timezone.utc)
        if self.state_file.exists():
            try:
                with open(self.state_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    return CapacityAcquisitionState.from_dict(data)
            except Exception:
                pass

        started_iso = now_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        expires_dt = now_dt + timedelta(seconds=self.config.max_duration_seconds)
        expires_iso = expires_dt.strftime("%Y-%m-%dT%H:%M:%SZ")

        new_state = CapacityAcquisitionState(
            status=STATE_PENDING,
            started_at=started_iso,
            expires_at=expires_iso,
            next_eligible_at=started_iso,
        )
        self._save_state(new_state)
        return new_state

    def _save_state(self, state: CapacityAcquisitionState):
        tmp_file = self.state_file.with_suffix(".tmp")
        with open(tmp_file, "w", encoding="utf-8") as f:
            json.dump(state.to_dict(), f, indent=2)
        tmp_file.replace(self.state_file)
        self.state = state

    def check_eligibility(self, now: datetime | None = None) -> tuple[bool, str]:
        """Check whether a new provisioning attempt is permitted under policy constraints.

        Returns (is_eligible, reason)
        """
        now_dt = now or datetime.now(timezone.utc)
        now_iso = now_dt.strftime("%Y-%m-%dT%H:%M:%SZ")

        if self.state.status == STATE_ACQUIRED:
            return False, f"instance '{self.config.instance_name}' already successfully acquired; retries stopped"

        if self.state.status == STATE_EXPIRED or now_iso >= self.state.expires_at:
            if self.state.status != STATE_EXPIRED:
                self.state.status = STATE_EXPIRED
                self._save_state(self.state)
            return False, f"retry window has expired (exceeded 7 days lifetime limit; started {self.state.started_at})"

        if self.state.next_eligible_at and now_iso < self.state.next_eligible_at:
            return False, f"rate-governor cooldown active; next eligible attempt at {self.state.next_eligible_at} (min 60-min interval)"

        return True, "eligible for next capacity acquisition attempt"

    def verify_idempotency(self, existing_instances: list[dict[str, Any]]) -> bool:
        """Scan existing instances to detect if target instance was already provisioned.
        
        If found in PROVISIONING or RUNNING state, transitions status to ACQUIRED fail-safe.
        """
        for inst in existing_instances:
            name = inst.get("display_name") or inst.get("name")
            state = (inst.get("lifecycle_state") or inst.get("state") or "").upper()
            if name == self.config.instance_name and state in ("PROVISIONING", "RUNNING"):
                self.state.status = STATE_ACQUIRED
                self.state.acquired_instance_ocid = inst.get("id") or inst.get("ocid")
                self.state.acquired_public_ip = inst.get("public_ip")
                self.state.acquired_private_ip = inst.get("private_ip")
                self.state.acquired_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
                self._save_state(self.state)
                return True
        return False

    def record_attempt(
        self,
        outcome: str,
        *,
        error_message: str | None = None,
        instance_details: dict[str, Any] | None = None,
        now: datetime | None = None,
    ) -> CapacityAcquisitionState:
        """Record the outcome of a provisioning attempt and advance retry schedule."""
        now_dt = now or datetime.now(timezone.utc)
        now_iso = now_dt.strftime("%Y-%m-%dT%H:%M:%SZ")

        self.state.total_attempts += 1
        self.state.last_attempt_at = now_iso
        self.state.last_outcome = outcome
        self.state.last_error_message = error_message

        attempt_record: dict[str, Any] = {
            "attempt_number": self.state.total_attempts,
            "attempted_at": now_iso,
            "outcome": outcome,
            "error_message": error_message,
        }

        if outcome == OUTCOME_SUCCESS:
            self.state.status = STATE_ACQUIRED
            self.state.consecutive_out_of_capacity = 0
            self.state.consecutive_api_errors = 0
            self.state.next_eligible_at = None
            self.state.acquired_at = now_iso
            if instance_details:
                self.state.acquired_instance_ocid = instance_details.get("ocid") or instance_details.get("id")
                self.state.acquired_public_ip = instance_details.get("public_ip")
                self.state.acquired_private_ip = instance_details.get("private_ip")
                attempt_record["details"] = instance_details

        elif outcome == OUTCOME_OUT_OF_CAPACITY:
            self.state.status = STATE_RETRYING
            self.state.consecutive_out_of_capacity += 1
            self.state.consecutive_api_errors = 0
            # Standard 60-minute interval on out-of-capacity
            next_dt = now_dt + timedelta(seconds=self.config.min_interval_seconds)
            self.state.next_eligible_at = next_dt.strftime("%Y-%m-%dT%H:%M:%SZ")

        elif outcome in (OUTCOME_THROTTLED, OUTCOME_API_ERROR):
            self.state.status = STATE_THROTTLED if outcome == OUTCOME_THROTTLED else STATE_FAILED
            self.state.consecutive_api_errors += 1
            # Exponential backoff for throttling / API errors
            backoff_exp = self.config.initial_backoff_seconds * (self.config.backoff_multiplier ** (self.state.consecutive_api_errors - 1))
            backoff_seconds = min(self.config.max_backoff_seconds, max(self.config.min_interval_seconds, int(backoff_exp)))
            next_dt = now_dt + timedelta(seconds=backoff_seconds)
            self.state.next_eligible_at = next_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
            attempt_record["backoff_seconds"] = backoff_seconds

        else:
            raise ValueError(f"unsupported attempt outcome: {outcome!r}")

        # Check if new next_eligible_at exceeds 7-day expiration
        if self.state.next_eligible_at and self.state.next_eligible_at >= self.state.expires_at:
            self.state.status = STATE_EXPIRED
            self.state.next_eligible_at = None

        self.state.attempt_history.append(attempt_record)
        self._save_state(self.state)
        return self.state

    def get_summary(self, now: datetime | None = None) -> dict[str, Any]:
        """Generate structured status report for operator and audit artifacts."""
        now_dt = now or datetime.now(timezone.utc)
        now_iso = now_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        eligible, reason = self.check_eligibility(now_dt)

        return {
            "status": self.state.status,
            "target": {
                "instance_name": self.config.instance_name,
                "shape": self.config.shape,
                "ocpus": self.config.ocpus,
                "memory_gb": self.config.memory_in_gbs,
                "boot_volume_gb": self.config.boot_volume_gbs,
                "region": self.config.region,
                "availability_domain": self.config.availability_domain,
            },
            "schedule": {
                "started_at": self.state.started_at,
                "expires_at": self.state.expires_at,
                "min_interval_minutes": self.config.min_interval_seconds // 60,
                "max_duration_days": self.config.max_duration_seconds // 86400,
                "current_time": now_iso,
                "next_eligible_at": self.state.next_eligible_at,
                "is_currently_eligible": eligible,
                "eligibility_reason": reason,
            },
            "metrics": {
                "total_attempts": self.state.total_attempts,
                "consecutive_out_of_capacity": self.state.consecutive_out_of_capacity,
                "consecutive_api_errors": self.state.consecutive_api_errors,
                "last_attempt_at": self.state.last_attempt_at,
                "last_outcome": self.state.last_outcome,
                "last_error_message": self.state.last_error_message,
            },
            "acquisition": {
                "acquired": self.state.status == STATE_ACQUIRED,
                "acquired_at": self.state.acquired_at,
                "ocid": self.state.acquired_instance_ocid,
                "public_ip": self.state.acquired_public_ip,
                "private_ip": self.state.acquired_private_ip,
            },
        }
