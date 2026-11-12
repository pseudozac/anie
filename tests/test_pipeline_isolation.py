"""Strict cross-pipeline isolation, anti-contamination, and offline enforcement tests."""
from __future__ import annotations

from pathlib import Path
import socket
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from anie.demo import demo_observations
from anie.observations import Observation
from anie.publish import publish_synthetic
from anie.real_models import RealCollectionEvent, RealObservation
from anie.real_store import RealObservationStore
from test_real_models import sample_event, sample_observation


class TestPipelineIsolation(unittest.TestCase):
    def test_synthetic_observation_cannot_enter_real_store(self):
        with TemporaryDirectory() as tmp:
            store = RealObservationStore(Path(tmp) / "state_real.sqlite")
            synthetic_obs = demo_observations()[0]
            event = sample_event()

            # Attempting to insert synthetic Observation raises TypeError
            with self.assertRaisesRegex(TypeError, "synthetic Observation cannot enter"):
                store.insert_record(event, synthetic_obs)  # type: ignore

            with self.assertRaisesRegex(TypeError, "synthetic Observation cannot enter"):
                store.insert_batch([(event, synthetic_obs)])  # type: ignore

    def test_real_observation_cannot_enter_synthetic_publisher(self):
        real_obs = sample_observation()
        with TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "pub"
            # publish_synthetic requires a list of Observation; passing RealObservation
            # fails because RealObservation has synthetic=False and different schema
            with self.assertRaises((PermissionError, ValueError, AttributeError)):
                publish_synthetic([real_obs], out_dir, "2026-11-12T10:00:00Z")  # type: ignore

    def test_real_observation_cannot_masquerade_as_synthetic(self):
        # Even if someone constructs a dict with synthetic=True but method="dns"
        with self.assertRaisesRegex(ValueError, "synthetic origin must match synthetic method"):
            Observation.from_dict({
                "subject": "example.com",
                "kind": "dns_a",
                "observed_at": "2026-11-12T10:00:00Z",
                "values": ["93.184.216.34"],
                "status": "ok",
                "source_id": "spoofed_source",
                "method": "dns",
                "synthetic": True,
            })

    def test_real_observation_synthetic_flag_always_false(self):
        with self.assertRaisesRegex(ValueError, "synthetic=False"):
            sample_observation(synthetic=True)

    def test_offline_enforcement_during_real_pipeline_operations(self):
        """Verify that real models and real store operations make ZERO network calls."""
        def guarded_connect(*args, **kwargs):
            raise RuntimeError("unexpected network socket attempt during offline operations!")

        with patch.object(socket.socket, "connect", side_effect=guarded_connect):
            with patch.object(socket, "create_connection", side_effect=guarded_connect):
                with TemporaryDirectory() as tmp:
                    store = RealObservationStore(Path(tmp) / "state_real.sqlite")
                    event = sample_event()
                    obs = sample_observation(event=event)

                    # Model creation, serialization, database write, read, and retention
                    self.assertTrue(store.insert_record(event, obs))
                    fetched = store.get_observation(obs.observation_id)
                    self.assertIsNotNone(fetched)
                    self.assertEqual(fetched.observation_id, obs.observation_id)
                    self.assertEqual(store.check_referential_integrity(), [])
                    store.prune_retention("2020-01-01T00:00:00Z", "2020-01-01T00:00:00Z")


if __name__ == "__main__":
    unittest.main()
