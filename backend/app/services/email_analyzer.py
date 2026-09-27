import re
import logging
from typing import List, Dict, Any, Tuple
import dns.resolver

from app.schemas.analysis import EvidenceItem, AnalysisResponse
from app.services.risk_engine import risk_engine
from app.services.explanation_engine import explanation_engine

logger = logging.getLogger("cyberguard.email")

# Social engineering urgency patterns
URGENCY_PATTERNS = [
    r"urgent", r"immediately", r"within \d+ hours?", r"action required",
    r"suspend", r"verify your", r"confirm your identity", r"unauthorized",
    r"unusual activity", r"locked", r"restricted", r"expire",
    r"click here", r"act now", r"limited time", r"final warning"
]

# Known legitimate domains that are commonly spoofed
SPOOFED_BRANDS = {
    "paypal": "paypal.com",
    "chase": "chase.com",
    "microsoft": "microsoft.com",
    "apple": "apple.com",
    "google": "google.com",
    "amazon": "amazon.com",
    "netflix": "netflix.com",
    "facebook": "facebook.com",
    "instagram": "instagram.com",
    "wells fargo": "wellsfargo.com",
    "bank of america": "bankofamerica.com",
}


class EmailAnalyzer:
    """
    CYBERGUARD Email Forensic Analyzer.
    Performs SPF record verification, sender domain reputation heuristics,
    header anomaly detection, and social engineering NLP scoring.
    """

    # ── SPF Record Verification via DNS ─────────────────────────────────
    def _verify_spf(self, sender_domain: str) -> Tuple[bool, str]:
        """
        Check if the sender domain has a valid SPF record.
        Missing SPF is a strong phishing indicator.
        Returns (has_spf: bool, spf_record: str).
        """
        try:
            answers = dns.resolver.resolve(sender_domain, "TXT")
            for record in answers:
                txt = record.to_text().strip('"')
                if "v=spf1" in txt:
                    return True, txt
        except dns.resolver.NXDOMAIN:
            logger.info(f"SPF check: Domain {sender_domain} does not exist (NXDOMAIN)")
            return False, "NXDOMAIN"
        except dns.resolver.NoAnswer:
            logger.debug(f"SPF check: No TXT records for {sender_domain}")
        except dns.resolver.LifetimeTimeout:
            logger.debug(f"SPF check: DNS timeout for {sender_domain}")
        except Exception as e:
            logger.debug(f"SPF check error for {sender_domain}: {e}")
        return False, ""

    # ── DMARC Record Check via DNS ──────────────────────────────────────
    def _check_dmarc(self, sender_domain: str) -> Tuple[bool, str]:
        """
        Check if the sender domain has a DMARC policy.
        Returns (has_dmarc: bool, dmarc_policy: str).
        """
        try:
            dmarc_domain = f"_dmarc.{sender_domain}"
            answers = dns.resolver.resolve(dmarc_domain, "TXT")
            for record in answers:
                txt = record.to_text().strip('"')
                if "v=DMARC1" in txt:
                    # Extract policy
                    policy = "none"
                    if "p=reject" in txt:
                        policy = "reject"
                    elif "p=quarantine" in txt:
                        policy = "quarantine"
                    elif "p=none" in txt:
                        policy = "none"
                    return True, policy
        except Exception:
            pass
        return False, ""

    # ── MX Record Check ─────────────────────────────────────────────────
    def _check_mx_records(self, sender_domain: str) -> Tuple[bool, List[str]]:
        """
        Check if the sender domain has valid MX records (can receive email).
        Phishing domains often lack MX records.
        Returns (has_mx: bool, mx_hosts: list).
        """
        try:
            answers = dns.resolver.resolve(sender_domain, "MX")
            mx_hosts = [str(record.exchange).rstrip(".") for record in answers]
            return True, mx_hosts
        except Exception:
            return False, []

    # ── Sender Domain Spoofing Heuristics ───────────────────────────────
    def _detect_brand_spoofing(self, sender: str, subject: str, body: str) -> List[EvidenceItem]:
        """Detect brand impersonation in sender address and content."""
        evidence = []
        sender_lower = sender.lower()
        combined_text = f"{sender_lower} {subject.lower()} {body.lower()}"

        for brand, legit_domain in SPOOFED_BRANDS.items():
            if brand in combined_text:
                sender_domain = sender.split("@")[-1] if "@" in sender else ""
                if sender_domain and sender_domain.lower() != legit_domain:
                    evidence.append(EvidenceItem(
                        indicator="brand_domain_impersonation",
                        description=f"Email references '{brand}' but originates from '{sender_domain}' instead of legitimate '{legit_domain}'",
                        weight=18
                    ))
                    break

        # Lookalike character substitution (e.g., paypa1 vs paypal, micr0soft)
        sender_domain = sender.split("@")[-1] if "@" in sender else sender
        if re.search(r"[0-9]", sender_domain):
            # Check if digits appear to substitute letters
            normalized = sender_domain.replace("0", "o").replace("1", "l").replace("3", "e").replace("5", "s")
            for brand in SPOOFED_BRANDS:
                if brand.replace(" ", "") in normalized and brand.replace(" ", "") not in sender_domain:
                    evidence.append(EvidenceItem(
                        indicator="homoglyph_substitution",
                        description=f"Sender domain '{sender_domain}' uses character substitution to mimic '{brand}'",
                        weight=16
                    ))
                    break

        return evidence

    # ── Social Engineering NLP Scoring ──────────────────────────────────
    def _score_social_engineering(self, subject: str, body: str) -> Tuple[float, List[EvidenceItem]]:
        """
        Score the email content for social engineering urgency tactics.
        Returns (se_score: float 0-1, evidence: list).
        """
        evidence = []
        combined = f"{subject} {body}".lower()
        matched_patterns = []

        for pattern in URGENCY_PATTERNS:
            if re.search(pattern, combined):
                matched_patterns.append(pattern)

        if len(matched_patterns) >= 3:
            evidence.append(EvidenceItem(
                indicator="high_urgency_social_engineering",
                description=f"Multiple social engineering urgency tactics detected ({len(matched_patterns)} patterns): coercive language designed to bypass rational decision-making",
                weight=16
            ))
        elif len(matched_patterns) >= 1:
            evidence.append(EvidenceItem(
                indicator="urgency_coercion_language",
                description=f"Social engineering urgency language detected ({len(matched_patterns)} pattern{'s' if len(matched_patterns) > 1 else ''}): {', '.join(matched_patterns[:3])}",
                weight=10
            ))

        # Check for suspicious link patterns in body
        url_count = len(re.findall(r"https?://\S+", body))
        if url_count > 0:
            evidence.append(EvidenceItem(
                indicator="embedded_external_links",
                description=f"{url_count} external URL(s) embedded in message body",
                weight=6
            ))

        # Check for attachment references
        if any(word in combined for word in ["attachment", "attached", "download", "open the file"]):
            evidence.append(EvidenceItem(
                indicator="attachment_lure",
                description="Email references file attachments, potential malware delivery vector",
                weight=8
            ))

        se_score = min(1.0, len(matched_patterns) / 6.0)
        return se_score, evidence

    def analyze_email(
        self,
        sender: str,
        subject: str,
        body: str
    ) -> AnalysisResponse:
        """Full email forensic analysis pipeline."""
        evidence: List[EvidenceItem] = []
        features: Dict[str, Any] = {}

        # Extract sender domain
        sender_domain = sender.split("@")[-1] if "@" in sender else sender
        features["sender_domain"] = sender_domain

        # 1. SPF verification
        has_spf, spf_record = self._verify_spf(sender_domain)
        features["spf_valid"] = has_spf
        if not has_spf:
            if spf_record == "NXDOMAIN":
                evidence.append(EvidenceItem(
                    indicator="sender_domain_nonexistent",
                    description=f"Sender domain '{sender_domain}' does not exist in DNS (NXDOMAIN). Confirmed spoofed sender.",
                    weight=22
                ))
            else:
                evidence.append(EvidenceItem(
                    indicator="missing_spf_record",
                    description=f"Sender domain '{sender_domain}' has no SPF record. Cannot verify sender authorization.",
                    weight=12
                ))
        else:
            if "-all" in spf_record:
                evidence.append(EvidenceItem(
                    indicator="strict_spf_policy",
                    description=f"Sender domain has strict SPF policy (-all): only authorized servers can send email",
                    weight=0
                ))
            features["spf_record"] = spf_record[:100]

        # 2. DMARC check
        has_dmarc, dmarc_policy = self._check_dmarc(sender_domain)
        features["dmarc_valid"] = has_dmarc
        features["dmarc_policy"] = dmarc_policy
        if not has_dmarc:
            evidence.append(EvidenceItem(
                indicator="missing_dmarc_policy",
                description=f"No DMARC policy configured for '{sender_domain}'. Domain is vulnerable to email spoofing.",
                weight=8
            ))

        # 3. MX record check
        has_mx, mx_hosts = self._check_mx_records(sender_domain)
        features["has_mx_records"] = has_mx
        if not has_mx:
            evidence.append(EvidenceItem(
                indicator="no_mail_exchange_records",
                description=f"Domain '{sender_domain}' has no MX records. Cannot receive replies — typical of throwaway phishing domains.",
                weight=14
            ))

        # 4. Brand spoofing detection
        brand_evidence = self._detect_brand_spoofing(sender, subject, body)
        evidence.extend(brand_evidence)

        # 5. Social engineering NLP
        se_score, se_evidence = self._score_social_engineering(subject, body)
        evidence.extend(se_evidence)
        features["social_engineering_score"] = round(se_score, 2)

        # Calculate overall probability
        total_weight = sum(e.weight for e in evidence)
        if total_weight == 0:
            proba = 0.05
        else:
            proba = min(0.98, max(0.05, 0.10 + (total_weight / 55.0)))

        risk_score, severity = risk_engine.calculate_risk(proba, evidence)
        prediction = "malicious" if risk_score >= 60 else ("suspicious" if risk_score >= 40 else "clean")

        actions = []
        if severity in ["CRITICAL", "HIGH"]:
            actions = ["block_sender", "quarantine_message", "notify_soc_team", "alert_targeted_user"]
        elif severity == "MEDIUM":
            actions = ["flag_message", "warn_recipient", "sandbox_attachments"]
        else:
            actions = ["deliver_normally", "update_allowlist"]

        explanation = explanation_engine.generate_explanation(
            threat_type="phishing",
            risk_score=risk_score,
            severity=severity,
            evidence=evidence,
            target_reference=f"Email from: {sender} | Subject: {subject[:60]}"
        )

        return AnalysisResponse(
            threat_type="phishing",
            prediction=prediction,
            confidence=round(proba, 2),
            risk_score=risk_score,
            severity=severity,
            evidence=evidence,
            recommended_actions=actions,
            explanation=explanation,
            mitre_technique="T1566",
            mitre_name="Phishing: Spearphishing via Email",
            features=features
        )


email_analyzer = EmailAnalyzer()
