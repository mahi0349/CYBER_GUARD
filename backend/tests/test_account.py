"""
Comprehensive Unit Tests for Scenario C: Account Takeover & Anomaly Detection.

Tests geo-velocity calculations (Haversine), brute force detection, device novelty,
MITRE ATT&CK mappings, Isolation Forest anomaly scoring, and end-to-end detector results.
"""

from datetime import datetime, timedelta, timezone
import unittest

from backend.data.account_samples import get_curated_account_samples
from backend.models.enums import ActionType, RiskLevel, ThreatCategory
from backend.models.schemas import AuthLogEntry, ThreatDetectionResult
from backend.modules.account_takeover.anomaly_model import (
    AnomalyModel,
    calculate_geo_velocity,
    calculate_haversine_distance,
)
from backend.modules.account_takeover.detector import AccountAnomalyDetector
from backend.modules.account_takeover.log_generator import SyntheticLogGenerator
from backend.modules.account_takeover.mitre_mapper import MitreAccountMapper


class TestGeoVelocity(unittest.TestCase):
    """Tests great-circle Haversine distance and travel speed calculations."""

    def test_haversine_distance_mumbai_london(self):
        """Mumbai to London is approximately 7,190 km."""
        lat_mumbai, lon_mumbai = 19.0760, 72.8777
        lat_london, lon_london = 51.5074, -0.1278

        dist = calculate_haversine_distance(lat_mumbai, lon_mumbai, lat_london, lon_london)
        self.assertGreater(dist, 7000.0)
        self.assertLess(dist, 7400.0)

    def test_impossible_travel_flagged(self):
        """7,200 km in 15 minutes is ~28,800 km/h, well beyond 850 km/h airliner ceiling."""
        t1 = datetime(2026, 9, 15, 10, 0, 0, tzinfo=timezone.utc)
        t2 = datetime(2026, 9, 15, 10, 15, 0, tzinfo=timezone.utc)

        geo = calculate_geo_velocity(19.0760, 72.8777, t1, 51.5074, -0.1278, t2)

        self.assertTrue(geo["is_impossible"])
        self.assertTrue(geo["is_supersonic"])
        self.assertGreater(geo["velocity_kmh"], 20000.0)

    def test_normal_commute_not_flagged(self):
        """30 km in 45 minutes is 40 km/h, perfectly normal driving."""
        t1 = datetime(2026, 9, 15, 8, 0, 0, tzinfo=timezone.utc)
        t2 = datetime(2026, 9, 15, 8, 45, 0, tzinfo=timezone.utc)

        # San Francisco to San Mateo
        geo = calculate_geo_velocity(37.7749, -122.4194, t1, 37.5630, -122.3255, t2)

        self.assertFalse(geo["is_impossible"])
        self.assertFalse(geo["is_supersonic"])
        self.assertLess(geo["velocity_kmh"], 80.0)


class TestSyntheticLogGenerator(unittest.TestCase):
    """Tests the synthetic authentication log generation engine."""

    def setUp(self):
        self.gen = SyntheticLogGenerator(seed=42)

    def test_normal_baseline_generation(self):
        logs = self.gen.generate_normal_baseline(username="user@corp.com", count=5)
        self.assertEqual(len(logs), 5)
        self.assertTrue(all(l.status == "SUCCESS" for l in logs))
        self.assertTrue(all(l.mfa_used for l in logs))
        self.assertEqual(len(set(l.device_fingerprint for l in logs)), 1)

    def test_impossible_travel_generation(self):
        logs = self.gen.generate_impossible_travel(
            username="traveler@corp.com",
            origin_city="Mumbai",
            dest_city="London",
            time_delta_minutes=10
        )
        self.assertEqual(len(logs), 3)
        self.assertEqual(logs[-1].city, "London")
        self.assertEqual(logs[0].city, "Mumbai")

    def test_brute_force_generation(self):
        logs = self.gen.generate_brute_force(
            username="target@corp.com",
            failed_attempts=8,
            final_success=True
        )
        self.assertEqual(len(logs), 9)
        self.assertEqual(sum(1 for l in logs if l.status == "FAILURE"), 8)
        self.assertEqual(logs[-1].status, "SUCCESS")


class TestAnomalyModel(unittest.TestCase):
    """Tests the hybrid rule and Isolation Forest model."""

    def setUp(self):
        self.model = AnomalyModel()
        self.gen = SyntheticLogGenerator(seed=77)

    def test_clean_logs_low_risk(self):
        normal_logs = self.gen.generate_normal_baseline(count=6)
        results = self.model.analyze_logs(normal_logs)

        self.assertLess(results["composite_score"], 0.35)
        self.assertEqual(len(results["impossible_travel_events"]), 0)
        self.assertEqual(len(results["brute_force_events"]), 0)

    def test_impossible_travel_detected(self):
        travel_logs = self.gen.generate_impossible_travel(time_delta_minutes=15)
        results = self.model.analyze_logs(travel_logs)

        self.assertGreaterEqual(results["composite_score"], 0.80)
        self.assertGreater(len(results["impossible_travel_events"]), 0)
        first_event = results["impossible_travel_events"][0]
        self.assertGreater(first_event["velocity_kmh"], 1000.0)

    def test_brute_force_detected(self):
        bf_logs = self.gen.generate_brute_force(failed_attempts=10, final_success=True)
        results = self.model.analyze_logs(bf_logs)

        self.assertGreaterEqual(results["composite_score"], 0.75)
        self.assertGreater(len(results["brute_force_events"]), 0)
        self.assertEqual(results["brute_force_events"][0]["final_status"], "SUCCESSFUL_COMPROMISE")


class TestMitreMapper(unittest.TestCase):
    """Tests mapping of anomalies to ATT&CK techniques."""

    def setUp(self):
        self.mapper = MitreAccountMapper()

    def test_safe_has_no_techniques(self):
        techniques = self.mapper.map_techniques({}, RiskLevel.SAFE)
        self.assertEqual(len(techniques), 0)

    def test_brute_force_techniques_mapped(self):
        results = {
            "brute_force_events": [{"failed_count": 8, "attacker_ips": ["198.51.100.10"]}]
        }
        techniques = self.mapper.map_techniques(results, RiskLevel.HIGH)
        self.assertTrue(any("T1110" in t for t in techniques))

    def test_impossible_travel_techniques_mapped(self):
        results = {
            "impossible_travel_events": [{"dest_city": "London"}]
        }
        techniques = self.mapper.map_techniques(results, RiskLevel.CRITICAL)
        self.assertTrue(any("T1078" in t for t in techniques))


class TestAccountAnomalyDetector(unittest.TestCase):
    """Tests end-to-end detection pipeline and output schemas."""

    def setUp(self):
        self.detector = AccountAnomalyDetector()
        self.gen = SyntheticLogGenerator(seed=12)

    def test_impossible_travel_critical_detection(self):
        logs = self.gen.generate_impossible_travel(username="exec@bank.com", time_delta_minutes=12)
        result = self.detector.analyze_logs(logs)

        self.assertIsInstance(result, ThreatDetectionResult)
        self.assertIn(result.risk_level, [RiskLevel.HIGH, RiskLevel.CRITICAL])
        self.assertGreaterEqual(result.risk_score, 80.0)
        self.assertEqual(result.category, ThreatCategory.ACCOUNT_TAKEOVER)
        self.assertIn("IMPOSSIBLE TRAVEL", result.human_explanation)

        # Check response actions include session revocation
        action_types = [a.action_type for a in result.recommended_actions]
        self.assertIn(ActionType.REVOKE_SESSION, action_types)
        self.assertIn(ActionType.REQUIRE_MFA, action_types)

    def test_legitimate_routine_safe(self):
        logs = self.gen.generate_normal_baseline(username="regular@corp.com", count=5)
        result = self.detector.analyze_logs(logs)

        self.assertIsInstance(result, ThreatDetectionResult)
        self.assertEqual(result.risk_level, RiskLevel.SAFE)
        self.assertLess(result.risk_score, 30.0)
        self.assertEqual(result.category, ThreatCategory.BENIGN)

        action_types = [a.action_type for a in result.recommended_actions]
        self.assertIn(ActionType.ALLOW, action_types)

    def test_curated_samples_pipeline(self):
        """Verify all curated sample scenarios execute properly through detector."""
        samples = get_curated_account_samples()
        self.assertGreaterEqual(len(samples), 4)

        for s in samples:
            log_entries = [AuthLogEntry(**entry) for entry in s["logs"]]
            res = self.detector.analyze_logs(log_entries)
            self.assertIsInstance(res, ThreatDetectionResult)
            self.assertIsNotNone(res.human_explanation)
            self.assertGreater(len(res.human_explanation), 20)


if __name__ == "__main__":
    unittest.main()
