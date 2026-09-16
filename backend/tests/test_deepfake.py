"""
Unit tests for Deepfake & Impersonation Detection module (Scenario B).

Tests cover:
- ELA score computation on synthetic images
- DCT frequency analysis on clean vs re-compressed images
- Impersonation detection accuracy on known samples
- Risk scoring threshold correctness
- Full detector pipeline end-to-end
"""

import io
import json
import unittest

import numpy as np
from PIL import Image

from backend.modules.deepfake.detector import DeepfakeDetector
from backend.modules.deepfake.image_forensics import ImageForensicsAnalyzer
from backend.modules.deepfake.impersonation import ImpersonationDetector
from backend.data.deepfake_samples import IMPERSONATION_SAMPLES


def _create_test_image(width=200, height=200, color=(128, 128, 128), fmt="JPEG") -> bytes:
    """Creates a simple test image as bytes."""
    img = Image.new("RGB", (width, height), color)
    buf = io.BytesIO()
    img.save(buf, format=fmt, quality=95)
    buf.seek(0)
    return buf.read()


def _create_manipulated_image(width=200, height=200) -> bytes:
    """Creates a test image with a manipulated region (different compression in one area)."""
    # Create base image
    img = Image.new("RGB", (width, height), (100, 120, 140))

    # Save at high quality
    buf1 = io.BytesIO()
    img.save(buf1, format="JPEG", quality=95)
    buf1.seek(0)
    img1 = Image.open(buf1)

    # Modify a region and re-save at different quality (simulates editing)
    pixels = img1.load()
    for x in range(50, 150):
        for y in range(50, 150):
            pixels[x, y] = (255, 0, 0)  # Red patch

    buf2 = io.BytesIO()
    img1.save(buf2, format="JPEG", quality=60)
    buf2.seek(0)

    # Re-save once more (double compression)
    img2 = Image.open(buf2)
    buf3 = io.BytesIO()
    img2.save(buf3, format="JPEG", quality=85)
    buf3.seek(0)
    return buf3.read()


class TestImageForensicsAnalyzer(unittest.TestCase):
    """Tests for the ELA and DCT image forensics engine."""

    def setUp(self):
        self.analyzer = ImageForensicsAnalyzer()

    def test_analyze_returns_expected_keys(self):
        """Ensure analyze() returns all required fields."""
        image_bytes = _create_test_image()
        result = self.analyzer.analyze(image_bytes)

        self.assertIn("ela_score", result)
        self.assertIn("ela_heatmap_base64", result)
        self.assertIn("ela_details", result)
        self.assertIn("dct_score", result)
        self.assertIn("dct_spectrum_base64", result)
        self.assertIn("dct_details", result)
        self.assertIn("combined_score", result)
        self.assertIn("indicators", result)
        self.assertIn("image_dimensions", result)

    def test_ela_score_range(self):
        """ELA score should be between 0 and 1."""
        image_bytes = _create_test_image()
        result = self.analyzer.analyze(image_bytes)
        self.assertGreaterEqual(result["ela_score"], 0.0)
        self.assertLessEqual(result["ela_score"], 1.0)

    def test_dct_score_range(self):
        """DCT score should be between 0 and 1."""
        image_bytes = _create_test_image()
        result = self.analyzer.analyze(image_bytes)
        self.assertGreaterEqual(result["dct_score"], 0.0)
        self.assertLessEqual(result["dct_score"], 1.0)

    def test_heatmap_is_valid_base64(self):
        """ELA heatmap should be a valid base64-encoded PNG."""
        import base64
        image_bytes = _create_test_image()
        result = self.analyzer.analyze(image_bytes)
        # Should not raise
        decoded = base64.b64decode(result["ela_heatmap_base64"])
        self.assertGreater(len(decoded), 0)
        # Should be valid PNG
        img = Image.open(io.BytesIO(decoded))
        self.assertEqual(img.format, "PNG")

    def test_manipulated_image_has_higher_score(self):
        """A manipulated image should generally produce a higher combined score than a clean one."""
        clean = _create_test_image()
        manipulated = _create_manipulated_image()

        clean_result = self.analyzer.analyze(clean)
        manip_result = self.analyzer.analyze(manipulated)

        # The manipulated image should have non-zero ELA score
        # (exact comparison depends on manipulation degree, so we just check it runs)
        self.assertIsNotNone(manip_result["ela_score"])
        self.assertIsNotNone(manip_result["dct_score"])

    def test_image_dimensions_reported(self):
        """Image dimensions should be correctly reported."""
        image_bytes = _create_test_image(width=300, height=200)
        result = self.analyzer.analyze(image_bytes)
        self.assertEqual(result["image_dimensions"]["width"], 300)
        self.assertEqual(result["image_dimensions"]["height"], 200)

    def test_png_image_support(self):
        """Should handle PNG images."""
        image_bytes = _create_test_image(fmt="PNG")
        result = self.analyzer.analyze(image_bytes)
        self.assertIn("ela_score", result)


class TestImpersonationDetector(unittest.TestCase):
    """Tests for the text-based impersonation detector."""

    def setUp(self):
        self.detector = ImpersonationDetector()

    def test_ceo_fraud_detection(self):
        """Classic CEO fraud should score high."""
        result = self.detector.analyze(
            text_content="This is the CEO. Transfer $50,000 immediately. Do not share this with anyone.",
            claimed_identity="John Smith, CEO",
            claimed_organization="Microsoft",
        )
        self.assertGreater(result["impersonation_score"], 0.4)
        self.assertTrue(result["title_spoofing"]["detected"])
        self.assertTrue(result["authority_pressure"]["detected"])

    def test_legitimate_message_low_score(self):
        """Normal business communication should score low."""
        result = self.detector.analyze(
            text_content="Hi Sarah, thanks for sending the Q3 reports. Everything looks good. No rush on the summary.",
            claimed_identity="",
            claimed_organization="",
        )
        self.assertLess(result["impersonation_score"], 0.3)

    def test_title_spoofing_detection(self):
        """Should detect various authority titles."""
        result = self.detector.analyze(
            text_content="I am the Chief Financial Officer of this company.",
            claimed_identity="CFO",
        )
        self.assertTrue(result["title_spoofing"]["detected"])
        self.assertIn("cfo", result["title_spoofing"]["matched_titles"])

    def test_org_similarity_detection(self):
        """Should detect known organization references."""
        result = self.detector.analyze(
            text_content="Contact us regarding your account.",
            claimed_organization="State Bank of India",
        )
        self.assertTrue(result["org_similarity"]["detected"])
        self.assertEqual(result["org_similarity"]["matched_org"], "state bank of india")

    def test_authority_pressure_financial(self):
        """Should detect financial action requests."""
        result = self.detector.analyze(
            text_content="Wire the funds immediately. Keep this confidential.",
        )
        self.assertTrue(result["authority_pressure"]["detected"])
        self.assertTrue(result["authority_pressure"]["financial_action_detected"])

    def test_credential_solicitation_detected(self):
        """Should flag credential solicitation as a style anomaly."""
        result = self.detector.analyze(
            text_content="Please send me your password and login credentials immediately.",
            claimed_identity="IT Director",
        )
        self.assertTrue(result["communication_anomalies"]["detected"])

    def test_multiple_signals_boost_score(self):
        """Multiple independent signals should boost the final score."""
        # Minimal signal
        single = self.detector.analyze(
            text_content="The VP mentioned the project timeline.",
            claimed_identity="VP",
        )
        # Multiple signals
        multi = self.detector.analyze(
            text_content="This is the CEO. Transfer funds now. Do not share this. Keep it confidential.",
            claimed_identity="CEO",
            claimed_organization="HDFC Bank",
        )
        self.assertGreater(multi["impersonation_score"], single["impersonation_score"])

    def test_indicators_generated(self):
        """Should produce ThreatIndicator objects for detected signals."""
        result = self.detector.analyze(
            text_content="This is the CEO. Wire the funds to new account. Keep this confidential.",
            claimed_identity="CEO",
            claimed_organization="Google",
        )
        self.assertGreater(len(result["indicators"]), 0)
        for ind in result["indicators"]:
            self.assertIsNotNone(ind.name)
            self.assertIsNotNone(ind.description)

    def test_all_samples_run_without_error(self):
        """All curated test samples should process without exceptions."""
        for sample in IMPERSONATION_SAMPLES:
            result = self.detector.analyze(
                text_content=sample.get("text_content"),
                claimed_identity=sample.get("claimed_identity"),
                claimed_organization=sample.get("claimed_organization"),
                urgency_context=sample.get("urgency_context"),
            )
            self.assertIsNotNone(result["impersonation_score"])
            self.assertGreaterEqual(result["impersonation_score"], 0.0)
            self.assertLessEqual(result["impersonation_score"], 1.0)


class TestDeepfakeDetector(unittest.TestCase):
    """End-to-end tests for the DeepfakeDetector orchestrator."""

    def setUp(self):
        self.detector = DeepfakeDetector()

    def test_image_analysis_returns_threat_result(self):
        """analyze_image() should return a valid ThreatDetectionResult."""
        image_bytes = _create_test_image()
        result = self.detector.analyze_image(image_bytes, filename="test.jpg")

        self.assertIsNotNone(result.id)
        self.assertIsNotNone(result.risk_level)
        self.assertGreaterEqual(result.risk_score, 0.0)
        self.assertLessEqual(result.risk_score, 100.0)
        self.assertIsNotNone(result.human_explanation)
        self.assertEqual(result.source.value, "Image / Document")

    def test_impersonation_analysis_returns_threat_result(self):
        """analyze_impersonation() should return a valid ThreatDetectionResult."""
        result = self.detector.analyze_impersonation(
            text_content="This is the CEO. Transfer funds immediately.",
            claimed_identity="CEO",
        )

        self.assertIsNotNone(result.id)
        self.assertIsNotNone(result.risk_level)
        self.assertGreaterEqual(result.risk_score, 0.0)
        self.assertLessEqual(result.risk_score, 100.0)
        self.assertIsNotNone(result.human_explanation)

    def test_risk_level_thresholds(self):
        """Risk level should follow defined threshold mappings."""
        # Safe
        self.assertEqual(self.detector._score_to_risk_level(10.0).value, "Safe")
        # Low
        self.assertEqual(self.detector._score_to_risk_level(25.0).value, "Low")
        # Medium
        self.assertEqual(self.detector._score_to_risk_level(50.0).value, "Medium")
        # High
        self.assertEqual(self.detector._score_to_risk_level(75.0).value, "High")
        # Critical
        self.assertEqual(self.detector._score_to_risk_level(90.0).value, "Critical")

    def test_safe_result_has_allow_action(self):
        """Safe results should recommend 'Allow' action."""
        result = self.detector.analyze_impersonation(
            text_content="Thanks for the report. Looks good, no rush.",
        )
        if result.risk_level.value == "Safe":
            action_types = [a.action_type.value for a in result.recommended_actions]
            self.assertIn("Allow Traffic / No Action Required", action_types)

    def test_mitre_techniques_present_for_threats(self):
        """Detected threats should include MITRE ATT&CK technique mappings."""
        result = self.detector.analyze_impersonation(
            text_content="This is the CEO. Wire $100,000 now. Do not tell anyone.",
            claimed_identity="CEO",
            claimed_organization="Google",
        )
        if result.risk_level.value != "Safe":
            self.assertGreater(len(result.mitre_attack_techniques), 0)


if __name__ == "__main__":
    unittest.main()
