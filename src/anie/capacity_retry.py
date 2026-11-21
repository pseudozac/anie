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
    availability_domain: str = "newE:AP-HYDERABAD-1-AD-1"
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

    def __enter__(self) -> bool:
        acquired = self.acquire()
        if not acquired:
            raise BlockingIOError("Could not acquire capacity acquisition lock (another instance is running).")
        return True

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.release()


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

    def run_cycle(
        self,
        provisioner: OciProvisioner | None = None,
        ssh_public_key_path: Path | str | None = None,
        *,
        force: bool = False,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        """Execute one complete unattended capacity acquisition cycle.

        Guarantees:
        - Mutual exclusion file lock held during the attempt.
        - Expiration and rate-limit cooldown verification.
        - OCI-side idempotency verification (reconciles already-launched instance).
        - Durable state advancement with next retry window.
        """
        now_dt = now or datetime.now(timezone.utc)
        result: dict[str, Any] = {
            "timestamp": now_dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "cycle_executed": False,
            "outcome": None,
            "message": "",
        }

        with self.lock:
            self.state = self._load_or_initialize_state(now_dt)

            if self.state.status == STATE_ACQUIRED:
                result["outcome"] = OUTCOME_SUCCESS
                result["message"] = f"Instance {self.config.instance_name} already acquired ({self.state.acquired_instance_ocid})."
                return result

            eligible, reason = self.check_eligibility(now_dt)
            if not eligible and not force:
                result["message"] = f"Skipping cycle: {reason}"
                return result

            # Resolve SSH public key
            resolved_key_path: Path | None = None
            candidate_paths = [
                Path(ssh_public_key_path) if ssh_public_key_path else None,
                Path.home() / ".ssh" / "anie-arm-01.key.pub",
                Path(".anie-capacity/anie-arm-01.key.pub"),
                Path("ssh-key-2026-11-21.key.pub"),
            ]
            for p in candidate_paths:
                if p and p.exists():
                    resolved_key_path = p
                    break

            if not resolved_key_path:
                msg = "SSH public key not found in candidate paths (~/.ssh/anie-arm-01.key.pub, .anie-capacity/, etc.)"
                self.record_attempt(OUTCOME_API_ERROR, error_message=msg, now=now_dt)
                result["outcome"] = OUTCOME_API_ERROR
                result["message"] = msg
                return result

            ssh_keys = resolved_key_path.read_text(encoding="utf-8").strip()
            prov = provisioner or OciProvisioner()

            try:
                resources = prov.resolve_resources(
                    compartment_name=self.config.compartment_name,
                    subnet_name=self.config.subnet_name,
                )
            except Exception as exc:
                msg = f"Failed to resolve OCI resources: {exc}"
                self.record_attempt(OUTCOME_API_ERROR, error_message=msg, now=now_dt)
                result["outcome"] = OUTCOME_API_ERROR
                result["message"] = msg
                return result

            # Idempotency check: see if instance is already created on OCI
            try:
                existing = prov.find_instance(resources["compartment_id"], self.config.instance_name)
            except Exception:
                existing = None

            if existing:
                self.verify_idempotency([existing])
                result["cycle_executed"] = True
                result["outcome"] = OUTCOME_SUCCESS
                result["message"] = f"Idempotency verified: target instance already exists on OCI in state {existing.get('state')} (OCID: {existing.get('ocid')})."
                return result

            # Attempt provisioning launch
            outcome, err_msg, inst_details = prov.attempt_launch(self.config, ssh_keys, resources)
            self.record_attempt(outcome, error_message=err_msg, instance_details=inst_details, now=now_dt)

            result["cycle_executed"] = True
            result["outcome"] = outcome
            result["message"] = err_msg or "Launch request accepted"
            result["next_eligible_at"] = self.state.next_eligible_at
            return result


class OciProvisioner:
    """Handles programmatic OCI API interactions for instance provisioning and idempotency."""

    def __init__(
        self,
        config_path: Path | str | None = None,
        profile_name: str = "DEFAULT",
        *,
        compute_client: Any = None,
        identity_client: Any = None,
        network_client: Any = None,
    ) -> None:
        self.config_path = config_path
        self.profile_name = profile_name
        self._compute_client = compute_client
        self._identity_client = identity_client
        self._network_client = network_client
        self._oci_config: dict[str, Any] | None = None

    def _get_clients(self) -> tuple[Any, Any, Any]:
        if self._compute_client and self._identity_client and self._network_client:
            return self._compute_client, self._identity_client, self._network_client

        try:
            import oci
        except ImportError as exc:
            raise RuntimeError("The 'oci' Python SDK is required for live OCI provisioning. Install via 'pip install oci'.") from exc

        if not self._oci_config:
            if self.config_path:
                self._oci_config = oci.config.from_file(file_location=str(self.config_path), profile_name=self.profile_name)
            else:
                self._oci_config = oci.config.from_file(profile_name=self.profile_name)

        if not self._compute_client:
            self._compute_client = oci.core.ComputeClient(self._oci_config)
        if not self._identity_client:
            self._identity_client = oci.identity.IdentityClient(self._oci_config)
        if not self._network_client:
            self._network_client = oci.core.VirtualNetworkClient(self._oci_config)

        return self._compute_client, self._identity_client, self._network_client

    def resolve_resources(
        self,
        compartment_name: str = "anie",
        subnet_name: str = "public subnet-anie-vcn",
    ) -> dict[str, str]:
        compute, identity, network = self._get_clients()
        tenancy_id = self._oci_config.get("tenancy", "") if self._oci_config else ""

        # Compartment
        comp_id = tenancy_id
        if compartment_name:
            comps = identity.list_compartments(tenancy_id).data
            for c in comps:
                if c.name == compartment_name and c.lifecycle_state == "ACTIVE":
                    comp_id = c.id
                    break

        # Availability Domain
        ads = identity.list_availability_domains(tenancy_id).data
        ad_name = ads[0].name if ads else ""

        # Subnet
        subnet_id = ""
        subnets = network.list_subnets(comp_id).data
        for s in subnets:
            if s.display_name == subnet_name and s.lifecycle_state == "AVAILABLE":
                subnet_id = s.id
                break
        if not subnet_id and subnets:
            subnet_id = subnets[0].id

        # Image
        images = compute.list_images(comp_id, operating_system="Oracle Linux", operating_system_version="9", shape="VM.Standard.A1.Flex").data
        arm_images = [img for img in images if "aarch64" in img.display_name.lower() or "arm" in img.display_name.lower()]
        image_id = arm_images[0].id if arm_images else (images[0].id if images else "")

        return {
            "compartment_id": comp_id,
            "availability_domain": ad_name,
            "subnet_id": subnet_id,
            "image_id": image_id,
        }

    def find_instance(self, compartment_id: str, instance_name: str) -> dict[str, Any] | None:
        compute, _, network = self._get_clients()
        instances = compute.list_instances(compartment_id, display_name=instance_name).data
        active = [i for i in instances if i.lifecycle_state not in ("TERMINATED", "TERMINATING")]
        if not active:
            return None
        inst = active[0]
        public_ip = None
        private_ip = None
        try:
            vnics = compute.list_vnic_attachments(compartment_id, instance_id=inst.id).data
            if vnics:
                vnic = network.get_vnic(vnics[0].vnic_id).data
                public_ip = vnic.public_ip
                private_ip = vnic.private_ip
        except Exception:
            pass

        return {
            "ocid": inst.id,
            "id": inst.id,
            "name": inst.display_name,
            "display_name": inst.display_name,
            "state": inst.lifecycle_state,
            "lifecycle_state": inst.lifecycle_state,
            "shape": inst.shape,
            "public_ip": public_ip,
            "private_ip": private_ip,
        }

    def attempt_launch(
        self,
        config: CapacityAcquisitionConfig,
        ssh_authorized_keys: str,
        resources: dict[str, str],
    ) -> tuple[str, str | None, dict[str, Any] | None]:
        compute, _, _ = self._get_clients()
        try:
            import oci
        except ImportError:
            return OUTCOME_API_ERROR, "oci sdk not installed", None

        launch_details = oci.core.models.LaunchInstanceDetails(
            compartment_id=resources["compartment_id"],
            availability_domain=resources["availability_domain"],
            display_name=config.instance_name,
            shape=config.shape,
            shape_config=oci.core.models.LaunchInstanceShapeConfigDetails(
                ocpus=float(config.ocpus),
                memory_in_gbs=float(config.memory_in_gbs),
            ),
            source_details=oci.core.models.InstanceSourceViaImageDetails(
                source_type="image",
                image_id=resources["image_id"],
                boot_volume_size_in_gbs=config.boot_volume_gbs,
            ),
            create_vnic_details=oci.core.models.CreateVnicDetails(
                subnet_id=resources["subnet_id"],
                assign_public_ip=config.assign_public_ip,
                display_name=f"{config.instance_name}-vnic",
            ),
            metadata={"ssh_authorized_keys": ssh_authorized_keys.strip()},
        )

        try:
            resp = compute.launch_instance(launch_details)
            inst = resp.data
            return OUTCOME_SUCCESS, None, {
                "ocid": inst.id,
                "name": inst.display_name,
                "state": inst.lifecycle_state,
                "shape": inst.shape,
            }
        except oci.exceptions.ServiceError as exc:
            msg = str(exc.message or exc)
            if exc.status == 500 or "out of host capacity" in msg.lower():
                return OUTCOME_OUT_OF_CAPACITY, f"Out of host capacity ({exc.code}: {msg})", None
            elif exc.status == 429 or "toomanyrequests" in msg.lower():
                return OUTCOME_THROTTLED, f"Throttled ({exc.code}: {msg})", None
            else:
                return OUTCOME_API_ERROR, f"OCI API error ({exc.status} {exc.code}: {msg})", None
        except Exception as exc:
            return OUTCOME_API_ERROR, f"Unexpected error: {exc}", None
