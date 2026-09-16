import unittest
from backend.models.enums import RiskLevel, ThreatCategory
from backend.models.schemas import PhishingAnalysisRequest
from backend.modules.phishing.detector import PhishingDetector

class TestPhishingDetection(unittest.TestCase):
    def setUp(self):
        self.detector = PhishingDetector()

    def test_credential_harvesting_phishing(self):
        req = PhishingAnalysisRequest(
            subject="CRITICAL: Microsoft 365 Password Expiring in 2 Hours",
            text="Your Office 365 password is scheduled to expire today. Please verify your login credentials immediately: http://login.micros0ft-verify.com/auth/login.php?user=target",
            sender="security-alert@micros0ft-verify.com",
            urls=["http://login.micros0ft-verify.com/auth/login.php?user=target"]
        )
        res = self.detector.analyze(req)
        
        self.assertIn(res.risk_level, [RiskLevel.HIGH, RiskLevel.CRITICAL])
        self.assertGreaterEqual(res.risk_score, 60.0)
        self.assertIn("T1566", " ".join(res.mitre_attack_techniques))
        self.assertTrue(any(a.action_type.value.startswith("Quarantine") or a.action_type.value.startswith("Block") for a in res.recommended_actions))
        self.assertIn("Risk", res.human_explanation)

    def test_banking_dispute_phishing(self):
        req = PhishingAnalysisRequest(
            subject="Unauthorized Transaction Alert - $849.99",
            text="We detected an unauthorized transaction. Confirm your identity, card number, and CVV code at http://paypa1-resolution-center.net/dispute",
            sender="service@paypa1-resolution-center.net",
            urls=["http://paypa1-resolution-center.net/dispute"]
        )
        res = self.detector.analyze(req)
        
        self.assertIn(res.risk_level, [RiskLevel.HIGH, RiskLevel.CRITICAL])
        self.assertTrue(any(ind.name == "Look-Alike / Typo-Squatted Domain" or "Payment Card" in ind.name for ind in res.indicators))

    def test_legitimate_newsletter(self):
        req = PhishingAnalysisRequest(
            subject="[GitHub] A new personal access token was created on your account",
            text="Hi Alex, A new token was created. If you generated this token, no action is needed. View settings at https://github.com/settings/tokens",
            sender="notifications@github.com",
            urls=["https://github.com/settings/tokens"]
        )
        res = self.detector.analyze(req)
        
        self.assertEqual(res.risk_level, RiskLevel.SAFE)
        self.assertLess(res.risk_score, 25.0)
        self.assertEqual(res.category, ThreatCategory.BENIGN)

    def test_ml_evaluation_metrics(self):
        metrics = self.detector.ml_classifier.evaluate()
        self.assertGreaterEqual(metrics["accuracy"], 0.90)
        self.assertGreaterEqual(metrics["precision"], 0.90)
        self.assertGreaterEqual(metrics["recall"], 0.90)
        self.assertGreaterEqual(metrics["f1_score"], 0.90)

if __name__ == "__main__":
    unittest.main()
