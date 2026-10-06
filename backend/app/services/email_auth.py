"""
CYBERGUARD Email Authenticity Analyzer.

Parses raw .eml content and performs header-level authenticity checks:
  - SPF / DKIM / DMARC from Authentication-Results header
  - From vs Reply-To vs Return-Path domain mismatch
  - Display-name impersonation detection
  - Lookalike / homoglyph domain detection
  - Header anomalies (missing Message-ID, excessive hops, date skew)

Returns a structured result compatible with the existing risk engine.
"""

import re
import logging
from email import policy, message_from_string
from email.utils import parseaddr, parsedate_to_datetime
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional, Tuple

from app.schemas.analysis import EvidenceItem, AnalysisResponse
from app.services.risk_engine import risk_engine
from app.services.explanation_engine import explanation_engine

logger = logging.getLogger("cyberguard.email_auth")

# ── Configurable Allowlist ──────────────────────────────────────────────
DOMAIN_ALLOWLIST = [
    "odisha.gov.in", "gov.in", "nic.in", "bfriendsb.co.in",
    "sbi.co.in", "onlinesbi.com", "hdfcbank.com", "icicibank.com",
    "axisbank.com", "pnbindia.in", "kotak.com", "yesbank.in",
    "rbi.org.in", "npci.org.in", "bfriendsb.co.in",
    "google.com", "microsoft.com", "apple.com", "amazon.com",
    "paypal.com", "chase.com", "wellsfargo.com", "bankofamerica.com",
]

FREEMAIL_DOMAINS = [
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com",
    "protonmail.com", "mail.com", "aol.com", "yandex.com",
    "zoho.com", "icloud.com", "gmx.com", "tutanota.com",
]

IMPERSONATION_TERMS = [
    "registrar", "vice chancellor", "chancellor", "bank", "government",
    "officer", "director", "chairman", "secretary", "finance",
    "accounts", "admin", "support", "helpdesk", "security",
    "verification", "compliance", "audit", "treasury",
]

# ── Homoglyph Mapping ──────────────────────────────────────────────────
HOMOGLYPH_MAP = {
    "0": "o", "1": "l", "3": "e", "5": "s", "8": "b",
    "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p", "\u0441": "c",  # Cyrillic
    "\u0443": "y", "\u0445": "x", "\u0456": "i", "\u0455": "s",
    "\u00e0": "a", "\u00e1": "a", "\u00e2": "a", "\u00e3": "a", "\u00e4": "a",
    "\u00e8": "e", "\u00e9": "e", "\u00ea": "e", "\u00eb": "e",
    "\u00f2": "o", "\u00f3": "o", "\u00f4": "o", "\u00f5": "o", "\u00f6": "o",
    "\u00ec": "i", "\u00ed": "i", "\u00ee": "i", "\u00ef": "i",
    "\u00f9": "u", "\u00fa": "u", "\u00fb": "u", "\u00fc": "u",
}


def _normalize_homoglyphs(text: str) -> str:
    """Replace homoglyph characters with their ASCII equivalents."""
    result = []
    for ch in text.lower():
        result.append(HOMOGLYPH_MAP.get(ch, ch))
    return "".join(result)


def _edit_distance(s1: str, s2: str) -> int:
    """Levenshtein edit distance."""
    if len(s1) < len(s2):
        return _edit_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)

    prev_row = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        curr_row = [i + 1]
        for j, c2 in enumerate(s2):
            cost = 0 if c1 == c2 else 1
            curr_row.append(min(
                curr_row[j] + 1,       # insert
                prev_row[j + 1] + 1,   # delete
                prev_row[j] + cost     # replace
            ))
        prev_row = curr_row
    return prev_row[-1]


def _extract_domain(address: str) -> str:
    """Extract domain from an email address string."""
    _, addr = parseaddr(address)
    if "@" in addr:
        return addr.split("@")[-1].lower().strip()
    return addr.lower().strip()


def _parse_auth_result(auth_header: str, mechanism: str) -> str:
    """
    Extract the result for a specific mechanism (spf, dkim, dmarc)
    from an Authentication-Results header.
    Returns 'pass', 'fail', 'softfail', 'neutral', 'none', or 'missing'.
    """
    if not auth_header:
        return "missing"

    # Match patterns like: spf=pass, dkim=fail, dmarc=none
    pattern = rf"{mechanism}\s*=\s*(\w+)"
    match = re.search(pattern, auth_header.lower())
    if match:
        return match.group(1)
    return "missing"


def analyze_email(raw_eml: str) -> dict:
    """
    Analyze a raw .eml string for email authenticity.

    Returns:
        dict with keys: score, level, findings, evidence, recommended_actions
    """
    findings: List[Dict[str, Any]] = []
    evidence_items: List[EvidenceItem] = []
    raw_evidence: Dict[str, Any] = {}

    # ── 1. Parse the email ──────────────────────────────────────────────
    try:
        msg = message_from_string(raw_eml, policy=policy.default)
    except Exception as e:
        logger.warning(f"Failed to parse email: {e}")
        return {
            "score": 0,
            "level": "Safe",
            "findings": [{
                "check": "email_parse",
                "status": "error",
                "detail": f"Could not parse email: {str(e)}",
                "weight": 0,
            }],
            "evidence": {},
            "recommended_actions": [],
        }

    # Extract key headers safely
    from_header = str(msg.get("From", "") or "")
    reply_to_header = str(msg.get("Reply-To", "") or "")
    return_path_header = str(msg.get("Return-Path", "") or "")
    auth_results_header = str(msg.get("Authentication-Results", "") or "")
    message_id = str(msg.get("Message-ID", "") or "")
    date_header = str(msg.get("Date", "") or "")
    received_headers = msg.get_all("Received") or []
    subject = str(msg.get("Subject", "") or "")

    from_display, from_addr = parseaddr(from_header)
    from_domain = _extract_domain(from_header)
    reply_to_domain = _extract_domain(reply_to_header) if reply_to_header else ""
    return_path_domain = _extract_domain(return_path_header) if return_path_header else ""

    raw_evidence["from"] = from_header
    raw_evidence["from_domain"] = from_domain
    raw_evidence["reply_to"] = reply_to_header
    raw_evidence["return_path"] = return_path_header
    raw_evidence["subject"] = subject
    raw_evidence["message_id"] = message_id
    raw_evidence["received_hops"] = len(received_headers)
    raw_evidence["authentication_results"] = auth_results_header

    # ── 2. SPF / DKIM / DMARC from Authentication-Results ──────────────
    spf_result = _parse_auth_result(auth_results_header, "spf")
    dkim_result = _parse_auth_result(auth_results_header, "dkim")
    dmarc_result = _parse_auth_result(auth_results_header, "dmarc")

    raw_evidence["spf"] = spf_result
    raw_evidence["dkim"] = dkim_result
    raw_evidence["dmarc"] = dmarc_result

    # SPF check
    if spf_result == "pass":
        findings.append({"check": "spf", "status": "pass", "detail": "SPF authentication passed", "weight": 0})
    elif spf_result == "missing":
        findings.append({"check": "spf", "status": "fail", "detail": "No SPF result found in Authentication-Results header", "weight": 10})
        evidence_items.append(EvidenceItem(indicator="spf_missing", description="No SPF authentication result present — sender authorization cannot be verified", weight=10))
    else:
        findings.append({"check": "spf", "status": "fail", "detail": f"SPF check returned '{spf_result}' — sender not authorized", "weight": 14})
        evidence_items.append(EvidenceItem(indicator="spf_fail", description=f"SPF authentication failed ({spf_result}): sending server not authorized for domain '{from_domain}'", weight=14))

    # DKIM check
    if dkim_result == "pass":
        findings.append({"check": "dkim", "status": "pass", "detail": "DKIM signature verified", "weight": 0})
    elif dkim_result == "missing":
        findings.append({"check": "dkim", "status": "fail", "detail": "No DKIM result found in Authentication-Results header", "weight": 8})
        evidence_items.append(EvidenceItem(indicator="dkim_missing", description="No DKIM signature result — message integrity cannot be verified", weight=8))
    else:
        findings.append({"check": "dkim", "status": "fail", "detail": f"DKIM verification returned '{dkim_result}' — signature invalid or absent", "weight": 12})
        evidence_items.append(EvidenceItem(indicator="dkim_fail", description=f"DKIM verification failed ({dkim_result}): message may have been tampered with in transit", weight=12))

    # DMARC check
    if dmarc_result == "pass":
        findings.append({"check": "dmarc", "status": "pass", "detail": "DMARC policy alignment passed", "weight": 0})
    elif dmarc_result == "missing":
        findings.append({"check": "dmarc", "status": "fail", "detail": "No DMARC result found in Authentication-Results header", "weight": 8})
        evidence_items.append(EvidenceItem(indicator="dmarc_missing", description="No DMARC policy result — domain owner has not configured alignment enforcement", weight=8))
    else:
        findings.append({"check": "dmarc", "status": "fail", "detail": f"DMARC alignment returned '{dmarc_result}' — policy not satisfied", "weight": 14})
        evidence_items.append(EvidenceItem(indicator="dmarc_fail", description=f"DMARC alignment failed ({dmarc_result}): email does not comply with domain's anti-spoofing policy", weight=14))

    # ── 3. From / Reply-To / Return-Path mismatch ──────────────────────
    domain_mismatch = False
    if reply_to_domain and reply_to_domain != from_domain:
        domain_mismatch = True
        findings.append({
            "check": "reply_to_mismatch",
            "status": "fail",
            "detail": f"Reply-To domain '{reply_to_domain}' differs from From domain '{from_domain}'",
            "weight": 12,
        })
        evidence_items.append(EvidenceItem(
            indicator="reply_to_domain_mismatch",
            description=f"Reply-To domain '{reply_to_domain}' does not match From domain '{from_domain}' — replies would be redirected to a different destination",
            weight=12,
        ))

    if return_path_domain and return_path_domain != from_domain:
        domain_mismatch = True
        findings.append({
            "check": "return_path_mismatch",
            "status": "fail",
            "detail": f"Return-Path domain '{return_path_domain}' differs from From domain '{from_domain}'",
            "weight": 10,
        })
        evidence_items.append(EvidenceItem(
            indicator="return_path_domain_mismatch",
            description=f"Return-Path domain '{return_path_domain}' does not match From domain '{from_domain}' — bounce handling domain is different",
            weight=10,
        ))

    if not domain_mismatch and (reply_to_domain or return_path_domain):
        findings.append({
            "check": "domain_alignment",
            "status": "pass",
            "detail": "From, Reply-To, and Return-Path domains are consistent",
            "weight": 0,
        })

    raw_evidence["reply_to_domain"] = reply_to_domain
    raw_evidence["return_path_domain"] = return_path_domain

    # ── 4. Display-name impersonation ──────────────────────────────────
    if from_display:
        display_lower = from_display.lower()
        matched_terms = [t for t in IMPERSONATION_TERMS if t in display_lower]
        if matched_terms and from_domain in FREEMAIL_DOMAINS:
            findings.append({
                "check": "display_name_impersonation",
                "status": "fail",
                "detail": f"Display name contains authority terms ({', '.join(matched_terms)}) but uses free-mail domain '{from_domain}'",
                "weight": 16,
            })
            evidence_items.append(EvidenceItem(
                indicator="display_name_impersonation",
                description=f"Display name '{from_display}' contains authority terms ({', '.join(matched_terms)}) but sends from free-mail domain '{from_domain}' — classic impersonation tactic",
                weight=16,
            ))
        elif matched_terms and from_domain not in DOMAIN_ALLOWLIST:
            # Not a free-mail but not in the allowlist either — moderate risk
            is_gov = from_domain.endswith(".gov.in") or from_domain.endswith(".nic.in")
            if not is_gov:
                findings.append({
                    "check": "display_name_impersonation",
                    "status": "warn",
                    "detail": f"Display name contains authority terms ({', '.join(matched_terms)}) from unrecognized domain '{from_domain}'",
                    "weight": 8,
                })
                evidence_items.append(EvidenceItem(
                    indicator="display_name_suspicious_domain",
                    description=f"Display name '{from_display}' claims authority ({', '.join(matched_terms)}) but domain '{from_domain}' is not in the recognized allowlist",
                    weight=8,
                ))
        else:
            if matched_terms:
                findings.append({
                    "check": "display_name_impersonation",
                    "status": "pass",
                    "detail": f"Display name contains authority terms but domain '{from_domain}' is in the allowlist",
                    "weight": 0,
                })

    # ── 5. Lookalike domain check ──────────────────────────────────────
    if from_domain and from_domain not in DOMAIN_ALLOWLIST and from_domain not in FREEMAIL_DOMAINS:
        normalized_from = _normalize_homoglyphs(from_domain)
        best_match: Optional[str] = None
        best_distance = 999

        for allowed in DOMAIN_ALLOWLIST:
            normalized_allowed = _normalize_homoglyphs(allowed)

            # Edit distance on the normalized forms
            dist = _edit_distance(normalized_from, normalized_allowed)
            if dist <= 3 and dist < best_distance:
                best_distance = dist
                best_match = allowed

            # Also check if homoglyph normalization makes them identical
            if normalized_from == normalized_allowed and from_domain != allowed:
                best_distance = 0
                best_match = allowed
                break

        if best_match is not None and best_distance > 0:
            weight = 18 if best_distance <= 1 else (14 if best_distance <= 2 else 10)
            findings.append({
                "check": "lookalike_domain",
                "status": "fail",
                "detail": f"From domain '{from_domain}' is {best_distance} edit(s) away from trusted domain '{best_match}'",
                "weight": weight,
            })
            evidence_items.append(EvidenceItem(
                indicator="lookalike_domain",
                description=f"Sender domain '{from_domain}' closely resembles trusted domain '{best_match}' (edit distance: {best_distance}) — potential typosquatting or homoglyph attack",
                weight=weight,
            ))
        elif best_match is not None and best_distance == 0:
            findings.append({
                "check": "homoglyph_domain",
                "status": "fail",
                "detail": f"From domain '{from_domain}' is a homoglyph of trusted domain '{best_match}'",
                "weight": 20,
            })
            evidence_items.append(EvidenceItem(
                indicator="homoglyph_domain_spoof",
                description=f"Sender domain '{from_domain}' uses homoglyph characters to impersonate trusted domain '{best_match}' — high-confidence spoofing attempt",
                weight=20,
            ))
        else:
            findings.append({
                "check": "lookalike_domain",
                "status": "pass",
                "detail": f"From domain '{from_domain}' does not closely resemble any trusted domain",
                "weight": 0,
            })

    # ── 6. Header anomalies ────────────────────────────────────────────
    # 6a. Missing Message-ID
    if not message_id or message_id.strip() == "":
        findings.append({
            "check": "missing_message_id",
            "status": "fail",
            "detail": "Email has no Message-ID header — unusual for legitimate mail servers",
            "weight": 8,
        })
        evidence_items.append(EvidenceItem(
            indicator="missing_message_id",
            description="No Message-ID header present — legitimate mail servers always generate a unique Message-ID",
            weight=8,
        ))
    else:
        findings.append({
            "check": "missing_message_id",
            "status": "pass",
            "detail": f"Message-ID present: {message_id[:60]}",
            "weight": 0,
        })

    # 6b. Excessive Received hops
    hop_count = len(received_headers)
    if hop_count > 8:
        findings.append({
            "check": "excessive_hops",
            "status": "fail",
            "detail": f"Email traversed {hop_count} mail servers (Received headers) — unusually high hop count",
            "weight": 6,
        })
        evidence_items.append(EvidenceItem(
            indicator="excessive_received_hops",
            description=f"Email passed through {hop_count} mail servers — excessive routing may indicate relay-based obfuscation",
            weight=6,
        ))
    else:
        findings.append({
            "check": "excessive_hops",
            "status": "pass",
            "detail": f"Received hop count ({hop_count}) is within normal range",
            "weight": 0,
        })

    # 6c. Date skew from first Received timestamp
    if date_header and received_headers:
        try:
            email_date = parsedate_to_datetime(date_header)
            # Parse timestamp from the first (oldest) Received header
            first_received = received_headers[-1] if received_headers else ""
            received_date_match = re.search(
                r";\s*(.+?)$", str(first_received), re.MULTILINE
            )
            if received_date_match:
                received_date_str = received_date_match.group(1).strip()
                received_date = parsedate_to_datetime(received_date_str)
                skew = abs((email_date - received_date).total_seconds())
                raw_evidence["date_skew_seconds"] = round(skew)

                if skew > 7200:  # 2 hours
                    findings.append({
                        "check": "date_skew",
                        "status": "fail",
                        "detail": f"Date header differs from first Received timestamp by {int(skew // 3600)}h {int((skew % 3600) // 60)}m — potential pre-dating/backdating",
                        "weight": 8,
                    })
                    evidence_items.append(EvidenceItem(
                        indicator="date_timestamp_skew",
                        description=f"Email Date header differs from the first Received timestamp by {int(skew // 60)} minutes — may indicate forged date or timezone manipulation",
                        weight=8,
                    ))
                else:
                    findings.append({
                        "check": "date_skew",
                        "status": "pass",
                        "detail": f"Date header and first Received timestamp are aligned (skew: {int(skew)}s)",
                        "weight": 0,
                    })
        except Exception as e:
            logger.debug(f"Date skew check failed: {e}")
            findings.append({
                "check": "date_skew",
                "status": "info",
                "detail": "Could not parse date headers for skew analysis",
                "weight": 0,
            })

    # ── 7. Calculate score via existing risk engine ─────────────────────
    total_weight = sum(e.weight for e in evidence_items)
    if total_weight == 0:
        ml_proba = 0.04
    else:
        ml_proba = min(0.98, max(0.05, 0.08 + (total_weight / 55.0)))

    risk_score, severity = risk_engine.calculate_risk(ml_proba, evidence_items)

    # Map severity to user-friendly level
    level_map = {
        "SAFE": "Safe",
        "LOW": "Low",
        "MEDIUM": "Medium",
        "HIGH": "High",
        "CRITICAL": "Critical",
    }
    level = level_map.get(severity, "Safe")

    # ── 8. Recommended actions ─────────────────────────────────────────
    recommended_actions: List[str] = []
    if severity in ["CRITICAL", "HIGH"]:
        recommended_actions = [
            "quarantine_email",
            "warn_user",
            "report_impersonation",
            "notify_soc",
        ]
    elif severity == "MEDIUM":
        recommended_actions = [
            "flag_for_review",
            "warn_user",
            "verify_sender_identity",
        ]
    elif severity == "LOW":
        recommended_actions = [
            "monitor_sender",
            "log_event",
        ]
    else:
        recommended_actions = [
            "deliver_normally",
        ]

    return {
        "score": risk_score,
        "level": level,
        "findings": findings,
        "evidence": raw_evidence,
        "recommended_actions": recommended_actions,
    }


def email_auth_to_analysis_response(result: dict, raw_eml_snippet: str) -> AnalysisResponse:
    """
    Convert the email_auth result dict into an AnalysisResponse
    compatible with the existing threat/incident persistence pipeline.
    """
    # Build EvidenceItem list from findings with weight > 0
    evidence = []
    for f in result.get("findings", []):
        if f.get("weight", 0) > 0:
            evidence.append(EvidenceItem(
                indicator=f["check"],
                description=f["detail"],
                weight=f["weight"],
            ))

    level = result.get("level", "Safe")
    severity_map = {
        "Safe": "SAFE", "Low": "LOW", "Medium": "MEDIUM",
        "High": "HIGH", "Critical": "CRITICAL",
    }
    severity = severity_map.get(level, "SAFE")
    score = result.get("score", 0)

    prediction = "malicious" if score >= 60 else ("suspicious" if score >= 40 else "clean")
    confidence = min(0.99, max(0.03, score / 100.0))

    explanation = explanation_engine.generate_explanation(
        threat_type="email_authenticity",
        risk_score=score,
        severity=severity,
        evidence=evidence,
        target_reference=f"Email from: {result.get('evidence', {}).get('from', 'unknown')}"
    )

    return AnalysisResponse(
        threat_type="email_authenticity",
        prediction=prediction,
        confidence=round(confidence, 2),
        risk_score=score,
        severity=severity,
        evidence=evidence,
        recommended_actions=result.get("recommended_actions", []),
        explanation=explanation,
        mitre_technique="T1566.001",
        mitre_name="Phishing: Spearphishing Attachment / Email Spoofing",
        features=result.get("evidence", {}),
    )
