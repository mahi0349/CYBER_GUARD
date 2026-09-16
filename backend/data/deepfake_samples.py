"""
Curated test samples for Deepfake & Impersonation detection module.

Provides one-click demo data for:
- Impersonation text messages (CEO fraud, vendor scam, IT spoofing)
- Legitimate text messages for comparison
- Sample image metadata references
"""

IMPERSONATION_SAMPLES = [
    # ── HIGH RISK: CEO Fraud / BEC Attack ────────────────────────────────
    {
        "id": "imp-001",
        "label": "phishing",
        "title": "🔴 CEO Fraud — Urgent Wire Transfer",
        "description": "Classic Business Email Compromise (BEC) impersonating CEO with urgent fund transfer request and secrecy directive.",
        "text_content": (
            "Dear Finance Team,\n\n"
            "This is the CEO. I am currently in a board meeting and cannot take calls. "
            "I need you to process an urgent wire transfer of $47,500 to a new vendor account immediately. "
            "The details are attached. Do NOT share this with anyone or verify through normal channels — "
            "this is a confidential acquisition and must be completed before end of business today.\n\n"
            "Do not discuss this with other team members. I will explain everything after the board meeting.\n\n"
            "Regards,\n"
            "James Morrison\n"
            "Chief Executive Officer"
        ),
        "claimed_identity": "James Morrison, CEO",
        "claimed_organization": "Microsoft",
        "urgency_context": "Immediate wire transfer before end of business"
    },
    # ── HIGH RISK: CFO Invoice Fraud ─────────────────────────────────────
    {
        "id": "imp-002",
        "label": "phishing",
        "title": "🔴 CFO Impersonation — Updated Payment Instructions",
        "description": "Impersonates CFO directing updated bank account details for vendor payments.",
        "text_content": (
            "URGENT: Action Required\n\n"
            "This is a direct instruction from the CFO's office. Effective immediately, all payments "
            "to Vertex Solutions Ltd must be redirected to new bank account details as follows:\n\n"
            "Account: 4892-7731-0056\n"
            "Routing: 021-000-089\n"
            "Bank: First National Trust\n\n"
            "This change is part of a confidential restructuring. Do not verify this through "
            "the vendor's previously known contacts. Process all pending invoices to the new account ASAP.\n\n"
            "Dr. Sarah Chen\n"
            "Chief Financial Officer"
        ),
        "claimed_identity": "Dr. Sarah Chen, CFO",
        "claimed_organization": "HDFC Bank",
        "urgency_context": "Redirect payments immediately, confidential restructuring"
    },
    # ── MEDIUM RISK: IT Department Credential Phishing ───────────────────
    {
        "id": "imp-003",
        "label": "phishing",
        "title": "🟠 IT Department — Password Reset Scam",
        "description": "Impersonates IT Head requesting password/credential submission via personal channel.",
        "text_content": (
            "Attention all employees,\n\n"
            "This is the Head of IT Security. Due to a critical security breach detected last night, "
            "all employees must immediately verify their credentials by replying to this email with:\n\n"
            "1. Your employee ID\n"
            "2. Current password\n"
            "3. VPN access credentials\n\n"
            "Failure to comply within 2 hours will result in automatic account suspension. "
            "For faster processing, you can also text me directly at +91-98765-43210.\n\n"
            "This is mandatory and time-sensitive.\n\n"
            "Rajesh Kumar\n"
            "Director, Information Technology"
        ),
        "claimed_identity": "Rajesh Kumar, Director IT",
        "claimed_organization": "Income Tax Department",
        "urgency_context": "Account suspension in 2 hours if not complied"
    },
    # ── MEDIUM RISK: Vendor Identity Fraud ───────────────────────────────
    {
        "id": "imp-004",
        "label": "phishing",
        "title": "🟠 Vendor Impersonation — Invoice Update",
        "description": "Impersonates known vendor with updated banking details for payment diversion.",
        "text_content": (
            "Dear Accounts Payable,\n\n"
            "I hope this message finds you well. I'm writing to inform you that our company, "
            "Reliance Jio Enterprise Solutions, has recently changed our banking partner. "
            "Please update your records with our new payment information for all future invoices:\n\n"
            "New Bank: Industrial Credit Corp\n"
            "Account Number: 7823-4561-8890\n"
            "IFSC: ICIC0001234\n\n"
            "Please process the three outstanding invoices (totaling ₹12,45,000) to the new account. "
            "Our previous bank account will be closed next week.\n\n"
            "Best regards,\n"
            "Amit Patel\n"
            "Senior Vice President — Enterprise Billing\n"
            "Reliance Jio"
        ),
        "claimed_identity": "Amit Patel, SVP Enterprise Billing",
        "claimed_organization": "Reliance Jio",
        "urgency_context": "Outstanding invoices need immediate payment redirect"
    },
    # ── LOW RISK: Mild Authority Reference ───────────────────────────────
    {
        "id": "imp-005",
        "label": "legitimate",
        "title": "🟡 Mild Authority Reference — Meeting Reminder",
        "description": "Contains authority title mention but no coercive pressure or financial request.",
        "text_content": (
            "Hi Team,\n\n"
            "Just a reminder that the VP of Engineering will be joining our standup tomorrow at 10am. "
            "Please prepare your sprint updates and have blockers documented.\n\n"
            "Thanks,\n"
            "Priya\n"
            "Engineering Manager"
        ),
        "claimed_identity": "Priya, Engineering Manager",
        "claimed_organization": "",
        "urgency_context": ""
    },
    # ── SAFE: Legitimate Internal Communication ──────────────────────────
    {
        "id": "imp-006",
        "label": "legitimate",
        "title": "🟢 Legitimate Internal — Project Update",
        "description": "Normal business communication with no impersonation indicators.",
        "text_content": (
            "Hi Sarah,\n\n"
            "Thank you for sending over the Q3 reports. I've reviewed the figures and everything looks "
            "good. I'll present the highlights at Thursday's team meeting.\n\n"
            "Could you also prepare a brief summary of the customer feedback we received last month? "
            "No rush — next week is fine.\n\n"
            "Best regards,\n"
            "David"
        ),
        "claimed_identity": "",
        "claimed_organization": "",
        "urgency_context": ""
    },
    # ── SAFE: Legitimate Org Reference ───────────────────────────────────
    {
        "id": "imp-007",
        "label": "legitimate",
        "title": "🟢 Legitimate — Standard Company Communication",
        "description": "References a real organization in normal, non-coercive business context.",
        "text_content": (
            "Dear Customer,\n\n"
            "Thank you for contacting State Bank of India customer support. Your request regarding "
            "the home loan EMI schedule has been processed. You can view the updated schedule in your "
            "SBI YONO app under Loans > EMI Schedule.\n\n"
            "If you have further questions, please visit your nearest branch or call our helpline "
            "at 1800-11-2211 (toll free).\n\n"
            "Regards,\n"
            "SBI Customer Care Team"
        ),
        "claimed_identity": "SBI Customer Care Team",
        "claimed_organization": "State Bank of India",
        "urgency_context": ""
    },
    # ── HIGH RISK: Government Authority Scam ─────────────────────────────
    {
        "id": "imp-008",
        "label": "phishing",
        "title": "🔴 Govt Authority — Tax Penalty Threat",
        "description": "Impersonates government tax authority with immediate penalty threat and demand for personal details.",
        "text_content": (
            "IMPORTANT NOTICE FROM THE INCOME TAX DEPARTMENT\n\n"
            "Dear Taxpayer,\n\n"
            "This is Commissioner R.K. Sharma from the Income Tax Department, Government of India. "
            "Our automated system has flagged your PAN (XXXXX1234X) for tax discrepancies in AY 2024-25. "
            "A penalty of ₹2,50,000 has been assessed.\n\n"
            "To avoid legal prosecution and asset seizure, you must immediately:\n"
            "1. Transfer ₹50,000 as compliance deposit to the account specified below\n"
            "2. Send your Aadhaar number and bank details for verification\n\n"
            "Account: 6745-8901-2345 (Government Treasury Account)\n"
            "IFSC: SBIN0001234\n\n"
            "This is confidential. Do not share with your CA or legal advisor as it may "
            "complicate the settlement process. Respond within 24 hours.\n\n"
            "Commissioner R.K. Sharma\n"
            "Income Tax Department\n"
            "Government of India"
        ),
        "claimed_identity": "Commissioner R.K. Sharma",
        "claimed_organization": "Income Tax Department",
        "urgency_context": "Legal prosecution and asset seizure within 24 hours"
    },
]

# Image test sample metadata (descriptions for UI — actual images are uploaded by user)
IMAGE_SAMPLE_INFO = [
    {
        "id": "img-info-001",
        "title": "Upload a Photo for Analysis",
        "description": (
            "Upload any JPEG or PNG image to run Error Level Analysis (ELA) and "
            "DCT Frequency-Domain forensics. The system will generate manipulation "
            "heatmaps and compression artifact analysis."
        ),
        "tips": [
            "Try uploading a photo that has been edited with filters or retouching",
            "Compare results between an original photo and its edited version",
            "Screenshots and re-saved images will show double-compression artifacts",
            "Profile photos downloaded from social media show re-compression patterns",
        ]
    }
]

# Combined export for API
DEEPFAKE_TEST_SAMPLES = {
    "impersonation_samples": IMPERSONATION_SAMPLES,
    "image_analysis_info": IMAGE_SAMPLE_INFO,
}
