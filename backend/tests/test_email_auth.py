"""
Unit tests for the email_auth module.
Tests each individual check: SPF/DKIM/DMARC parsing, domain mismatch,
display-name impersonation, lookalike domain, header anomalies,
and overall scoring. Also tests malformed email handling.
"""
import os
import io
import pytest

from app.services.email_auth import (
    analyze_email,
    _parse_auth_result,
    _extract_domain,
    _edit_distance,
    _normalize_homoglyphs,
    email_auth_to_analysis_response,
)


# ── Helper: load sample .eml files ─────────────────────────────────────
SAMPLES_DIR = os.path.join(os.path.dirname(__file__), "../../samples/emails")


def _load_sample(filename: str) -> str:
    path = os.path.join(SAMPLES_DIR, filename)
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


# ── Test: Authentication-Results parsing ───────────────────────────────
class TestAuthResultParsing:
    def test_spf_pass(self):
        header = "spf=pass (google.com) smtp.mailfrom=noreply@google.com; dkim=pass; dmarc=pass"
        assert _parse_auth_result(header, "spf") == "pass"

    def test_spf_fail(self):
        header = "spf=fail smtp.mailfrom=bad@evil.com; dkim=none; dmarc=fail"
        assert _parse_auth_result(header, "spf") == "fail"

    def test_dkim_pass(self):
        header = "spf=pass; dkim=pass header.d=google.com; dmarc=pass"
        assert _parse_auth_result(header, "dkim") == "pass"

    def test_dkim_missing(self):
        header = "spf=pass; dmarc=pass"
        assert _parse_auth_result(header, "dkim") == "missing"

    def test_dmarc_fail(self):
        header = "spf=pass; dkim=pass; dmarc=fail (p=REJECT)"
        assert _parse_auth_result(header, "dmarc") == "fail"

    def test_empty_header(self):
        assert _parse_auth_result("", "spf") == "missing"
        assert _parse_auth_result("", "dkim") == "missing"
        assert _parse_auth_result("", "dmarc") == "missing"

    def test_softfail(self):
        header = "spf=softfail smtp.mailfrom=x@evil.com"
        assert _parse_auth_result(header, "spf") == "softfail"


# ── Test: Domain extraction ────────────────────────────────────────────
class TestDomainExtraction:
    def test_simple_email(self):
        assert _extract_domain("user@example.com") == "example.com"

    def test_display_name_format(self):
        assert _extract_domain('"John Doe" <john@example.org>') == "example.org"

    def test_no_at_sign(self):
        assert _extract_domain("not-an-email") == "not-an-email"

    def test_empty(self):
        assert _extract_domain("") == ""


# ── Test: Edit distance ────────────────────────────────────────────────
class TestEditDistance:
    def test_identical(self):
        assert _edit_distance("abc", "abc") == 0

    def test_one_substitution(self):
        assert _edit_distance("onlinesbi.com", "onlinesbl.com") == 1

    def test_one_deletion(self):
        assert _edit_distance("google.com", "gogle.com") == 1

    def test_two_edits(self):
        assert _edit_distance("paypal.com", "paypa1.co") == 2

    def test_empty_strings(self):
        assert _edit_distance("", "") == 0
        assert _edit_distance("abc", "") == 3


# ── Test: Homoglyph normalization ──────────────────────────────────────
class TestHomoglyphNormalization:
    def test_digit_substitution(self):
        assert _normalize_homoglyphs("paypa1.com") == "paypal.com"

    def test_zero_to_o(self):
        assert _normalize_homoglyphs("g00gle.com") == "google.com"

    def test_no_change(self):
        assert _normalize_homoglyphs("google.com") == "google.com"

    def test_mixed_homoglyphs(self):
        assert _normalize_homoglyphs("micr0s0ft.com") == "microsoft.com"


# ── Test: Clean email analysis ─────────────────────────────────────────
class TestCleanEmail:
    def test_clean_sample(self):
        eml = _load_sample("01_clean_google_report.eml")
        result = analyze_email(eml)

        assert result["score"] < 20
        assert result["level"] == "Safe"

        # All auth checks should pass
        auth_checks = {f["check"]: f["status"] for f in result["findings"]}
        assert auth_checks.get("spf") == "pass"
        assert auth_checks.get("dkim") == "pass"
        assert auth_checks.get("dmarc") == "pass"


# ── Test: Spoofed registrar email ──────────────────────────────────────
class TestSpoofedRegistrar:
    def test_spoofed_sample(self):
        eml = _load_sample("02_spoofed_registrar.eml")
        result = analyze_email(eml)

        assert result["score"] >= 60
        assert result["level"] in ["High", "Critical"]

        # SPF should fail
        auth_checks = {f["check"]: f["status"] for f in result["findings"]}
        assert auth_checks.get("spf") == "fail"

        # Should detect reply-to mismatch
        findings_checks = [f["check"] for f in result["findings"]]
        assert "reply_to_mismatch" in findings_checks

        # Should detect return-path mismatch
        assert "return_path_mismatch" in findings_checks

        # Recommended actions should include quarantine
        assert "quarantine_email" in result["recommended_actions"]

    def test_display_name_impersonation(self):
        eml = _load_sample("02_spoofed_registrar.eml")
        result = analyze_email(eml)
        findings_checks = [f["check"] for f in result["findings"]]
        # Display name contains 'Registrar' from a non-allowlist domain
        assert "display_name_impersonation" in findings_checks


# ── Test: Lookalike bank domain ────────────────────────────────────────
class TestLookalikeDomain:
    def test_lookalike_bank_sample(self):
        eml = _load_sample("03_lookalike_bank.eml")
        result = analyze_email(eml)

        assert result["score"] >= 50
        assert result["level"] in ["Medium", "High", "Critical"]

        # Should detect lookalike domain
        findings_checks = [f["check"] for f in result["findings"]]
        assert "lookalike_domain" in findings_checks

        # SPF should not pass
        auth_checks = {f["check"]: f["status"] for f in result["findings"]}
        assert auth_checks.get("spf") != "pass"


# ── Test: Government impersonation ─────────────────────────────────────
class TestGovernmentImpersonation:
    def test_gov_impersonation_sample(self):
        eml = _load_sample("04_government_impersonation.eml")
        result = analyze_email(eml)

        assert result["score"] >= 60
        assert result["level"] in ["High", "Critical"]

        findings_checks = [f["check"] for f in result["findings"]]

        # Display name impersonation (government/finance on gmail.com)
        assert "display_name_impersonation" in findings_checks

        # Reply-To mismatch (gmail vs yahoo)
        assert "reply_to_mismatch" in findings_checks

        # Return-Path mismatch (protonmail)
        assert "return_path_mismatch" in findings_checks

        # Excessive hops (9+ Received headers)
        assert "excessive_hops" in findings_checks

    def test_all_auth_missing(self):
        eml = _load_sample("04_government_impersonation.eml")
        result = analyze_email(eml)
        auth_checks = {f["check"]: f["status"] for f in result["findings"]}
        # No Authentication-Results header → all should be missing/fail
        assert auth_checks.get("spf") == "fail" or auth_checks.get("spf") == "missing"


# ── Test: Malformed email handling ─────────────────────────────────────
class TestMalformedEmails:
    def test_empty_string(self):
        result = analyze_email("")
        assert isinstance(result, dict)
        assert "score" in result
        assert "level" in result

    def test_garbage_input(self):
        result = analyze_email("not an email at all\x00\x01\x02")
        assert isinstance(result, dict)
        assert result["level"] in ["Safe", "Low", "Medium", "High", "Critical"]

    def test_headers_only_no_body(self):
        eml = "From: test@example.com\nSubject: Test\n\n"
        result = analyze_email(eml)
        assert isinstance(result, dict)
        assert "findings" in result

    def test_unicode_content(self):
        eml = "From: тест@пример.com\nSubject: Тест Unicode\n\nBody with unicode: こんにちは"
        result = analyze_email(eml)
        assert isinstance(result, dict)

    def test_very_long_headers(self):
        eml = f"From: {'a' * 10000}@example.com\nSubject: {'B' * 5000}\n\nBody"
        result = analyze_email(eml)
        assert isinstance(result, dict)


# ── Test: AnalysisResponse conversion ──────────────────────────────────
class TestAnalysisResponseConversion:
    def test_clean_conversion(self):
        eml = _load_sample("01_clean_google_report.eml")
        result = analyze_email(eml)
        response = email_auth_to_analysis_response(result, "snippet")

        assert response.threat_type == "email_authenticity"
        assert response.severity == "SAFE"
        assert response.risk_score < 20
        assert response.mitre_technique == "T1566.001"

    def test_malicious_conversion(self):
        eml = _load_sample("02_spoofed_registrar.eml")
        result = analyze_email(eml)
        response = email_auth_to_analysis_response(result, "snippet")

        assert response.severity in ["HIGH", "CRITICAL"]
        assert response.prediction in ["malicious", "suspicious"]
        assert len(response.evidence) > 0
        assert response.explanation is not None


# ── Test: Inline constructed emails ────────────────────────────────────
class TestInlineEmails:
    def test_all_auth_pass(self):
        eml = (
            "Authentication-Results: mx.test.com; spf=pass; dkim=pass; dmarc=pass\r\n"
            "From: sender@google.com\r\n"
            "Reply-To: sender@google.com\r\n"
            "Return-Path: <sender@google.com>\r\n"
            "Message-ID: <abc123@google.com>\r\n"
            "Date: Mon, 06 Oct 2026 04:00:00 +0000\r\n"
            "Subject: Test\r\n"
            "\r\n"
            "Body text"
        )
        result = analyze_email(eml)
        assert result["score"] < 20
        assert result["level"] == "Safe"

    def test_all_auth_fail(self):
        eml = (
            "Authentication-Results: mx.test.com; spf=fail; dkim=fail; dmarc=fail\r\n"
            "From: attacker@evil.com\r\n"
            "Reply-To: different@other.com\r\n"
            "Return-Path: <bounce@another.com>\r\n"
            "Subject: URGENT\r\n"
            "\r\n"
            "Click here now"
        )
        result = analyze_email(eml)
        assert result["score"] >= 40
        findings_checks = [f["check"] for f in result["findings"]]
        assert "reply_to_mismatch" in findings_checks
        assert "return_path_mismatch" in findings_checks

    def test_freemail_impersonation(self):
        eml = (
            "From: \"Bank Manager - SBI\" <fake.bank.mgr@gmail.com>\r\n"
            "Message-ID: <test@gmail.com>\r\n"
            "Subject: Account\r\n"
            "\r\n"
            "Body"
        )
        result = analyze_email(eml)
        findings_checks = [f["check"] for f in result["findings"]]
        assert "display_name_impersonation" in findings_checks


# ── Test: API Endpoints ───────────────────────────────────────────────
class TestEmailAuthAPI:
    @pytest.fixture(autouse=True)
    def setup_client(self):
        from fastapi.testclient import TestClient
        from app.main import app
        self.client = TestClient(app)

    def test_post_email_analyze_raw_text(self):
        sample = _load_sample("01_clean_google_report.eml")
        res = self.client.post("/api/v1/email/analyze", data={"raw_text": sample})
        assert res.status_code == 200
        data = res.json()
        assert data["level"] == "Safe"
        assert "score" in data
        assert "findings" in data
        assert "evidence" in data

    def test_post_email_analyze_direct_api_prefix(self):
        sample = _load_sample("01_clean_google_report.eml")
        res = self.client.post("/api/email/analyze", data={"raw_text": sample})
        assert res.status_code == 200
        data = res.json()
        assert data["level"] == "Safe"

    def test_post_email_analyze_file_upload_incident_creation(self):
        sample = _load_sample("02_spoofed_registrar.eml")
        files = {"file": ("sample.eml", io.BytesIO(sample.encode("utf-8")), "message/rfc822")}
        res = self.client.post("/api/v1/email/analyze", files=files)
        assert res.status_code == 200
        data = res.json()
        assert data["level"] in ["High", "Critical"]
        # High/Critical incidents should have threat_id and incident_id created
        assert data.get("threat_id") is not None
        assert data.get("incident_id") is not None
        assert len(data.get("recommended_actions", [])) > 0

    def test_post_email_analyze_missing_input(self):
        res = self.client.post("/api/v1/email/analyze")
        assert res.status_code == 400

