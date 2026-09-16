"""
Comprehensive dataset of labeled Phishing and Legitimate samples
Used for training and evaluating the Scenario A Phishing Detection Module.
Each sample has: text, subject, sender, urls, label (1 = phishing, 0 = legitimate), category, and key indicators.
"""

TRAINING_AND_TEST_SAMPLES = [
    # --- PHISHING SAMPLES (Label: 1) ---
    {
        "id": "phish-001",
        "label": 1,
        "category": "Credential Harvesting",
        "sender": "security-alert@micros0ft-verify.com",
        "subject": "CRITICAL: Microsoft 365 Password Expiring in 2 Hours",
        "text": "Dear Valued User,\n\nYour Office 365 account password is scheduled to expire today. Failure to update your password within 2 hours will result in permanent suspension of your corporate email access and OneDrive files.\n\nPlease verify your login credentials immediately to maintain service continuity:\nhttp://login.micros0ft-verify.com/auth/login.php?user=target\n\nIT Security Operations Desk",
        "urls": ["http://login.micros0ft-verify.com/auth/login.php?user=target"]
    },
    {
        "id": "phish-002",
        "label": 1,
        "category": "Financial / Banking Phishing",
        "sender": "service@paypa1-resolution-center.net",
        "subject": "Notice of Unauthorized Transaction - $849.99 USD",
        "text": "Hello Customer,\n\nWe detected an unusual transaction of $849.99 on your PayPal account from an unrecognized IP in Moscow, Russia. If you did not authorize this payment, you must dispute it immediately to avoid permanent debits.\n\nClick below to confirm your identity, card number, and CVV code:\nhttp://paypa1-resolution-center.net/dispute/verify-identity.html\n\nPayPal Fraud Protection Team",
        "urls": ["http://paypa1-resolution-center.net/dispute/verify-identity.html"]
    },
    {
        "id": "phish-003",
        "label": 1,
        "category": "Brand Impersonation / Streaming",
        "sender": "billing-support@netfIix-update.xyz",
        "subject": "Your Netflix Membership is On Hold - Update Payment Method",
        "text": "We were unable to process your monthly subscription payment. Your Netflix streaming account will be deactivated within 24 hours unless you update your credit card details and billing address immediately.\n\nUpdate your payment info here:\nhttps://netfIix-update.xyz/account/billing-update\n\nNetflix Support",
        "urls": ["https://netfIix-update.xyz/account/billing-update"]
    },
    {
        "id": "phish-004",
        "label": 1,
        "category": "Delivery / Smishing Scam",
        "sender": "+18559283411",
        "subject": "USPS / FedEx Tracking Alert",
        "text": "USPS Alert: Package #9405510200883344 could not be delivered due to an incorrect house number. A fee of $1.50 is required for redelivery. Update your address and pay fee at: http://192.168.4.12/usps-redelivery/track within 12 hours.",
        "urls": ["http://192.168.4.12/usps-redelivery/track"]
    },
    {
        "id": "phish-005",
        "label": 1,
        "category": "Executive / Wire Fraud (BEC)",
        "sender": "ceo.office@company-corp-internal.co",
        "subject": "CONFIDENTIAL: Urgent Wire Transfer Request",
        "text": "Are you at your desk? I am currently in an executive board meeting and cannot take phone calls. I need you to initiate an urgent vendor payment of $42,500 for an acquisition closing by 3:00 PM today.\n\nReply directly with confirmation so I can send the overseas wiring instructions. Do not discuss this with anyone in accounting until closed.",
        "urls": []
    },
    {
        "id": "phish-006",
        "label": 1,
        "category": "Tax / Government Impersonation",
        "sender": "refunds@irs-tax-refund-portal.gov.top",
        "subject": "IRS Notification: Pending Tax Refund of $1,420.00",
        "text": "Internal Revenue Service Notice:\n\nOur records indicate you are eligible for an unclaimed tax refund of $1,420.00 from the previous fiscal year. To claim your refund directly to your bank account, verify your Social Security Number (SSN) and banking details:\nhttp://irs-tax-refund-portal.gov.top/claim/refund.aspx",
        "urls": ["http://irs-tax-refund-portal.gov.top/claim/refund.aspx"]
    },
    {
        "id": "phish-007",
        "label": 1,
        "category": "Tech Support / Malware",
        "sender": "helpdesk@google-drive-shared-file.club",
        "subject": "Security Breach Alert: Urgent Anti-Malware Patch Required",
        "text": "Google Security Team detected 4 trojan viruses attempting to exfiltrate your browser passwords. Download and run the critical security patch immediately:\nhttp://google-drive-shared-file.club/downloads/security-patch.exe\n\nFailure to patch will expose your sensitive data.",
        "urls": ["http://google-drive-shared-file.club/downloads/security-patch.exe"]
    },
    {
        "id": "phish-008",
        "label": 1,
        "category": "Social Engineering / Prize Scam",
        "sender": "rewards@amazon-gift-winner.buzz",
        "subject": "CONGRATULATIONS: You won a $1,000 Amazon Gift Card!",
        "text": "You have been selected as our Lucky Shopper of the Month! Claim your $1,000 Amazon Gift Card code today. Offer expires in 30 minutes! Click here: http://amazon-gift-winner.buzz/claim?code=AMZ1000 and enter your phone number and credit card to pay $1 shipping.",
        "urls": ["http://amazon-gift-winner.buzz/claim?code=AMZ1000"]
    },
    {
        "id": "phish-009",
        "label": 1,
        "category": "HR / Payroll Phishing",
        "sender": "payroll@workday-employee-portal.xyz",
        "subject": "Mandatory: Review Updated 2026 Direct Deposit Information",
        "text": "All employees are required to verify their direct deposit banking accounts by end of day for upcoming salary disbursements. Login to Workday portal to verify your routing number and SSN:\nhttp://workday-employee-portal.xyz/login/verify\n\nHuman Resources Department",
        "urls": ["http://workday-employee-portal.xyz/login/verify"]
    },
    {
        "id": "phish-010",
        "label": 1,
        "category": "Crypto / Wallet Drainer",
        "sender": "airdrop@metamask-security-sync.io",
        "subject": "Urgent: MetaMаsk Wallet Migration Required",
        "text": "Due to a network hard fork, all users must sync their secret recovery seed phrase to the new v4 protocol to avoid wallet deletion and loss of funds. Synchronize your 12-word seed phrase here:\nhttps://metamask-security-sync.io/vault/recovery\n\nMetaMask Decentralized Foundation",
        "urls": ["https://metamask-security-sync.io/vault/recovery"]
    },

    # --- LEGITIMATE SAMPLES (Label: 0) ---
    {
        "id": "legit-001",
        "label": 0,
        "category": "Service Notification",
        "sender": "notifications@github.com",
        "subject": "[GitHub] A new personal access token was created on your account",
        "text": "Hi Alex,\n\nA new personal access token (classic) 'CLI-deploy-token' was recently generated on your account alex-dev. If you generated this token, no action is needed.\n\nIf you did not generate this token, please visit https://github.com/settings/tokens to revoke it immediately.\n\nThanks,\nThe GitHub Team",
        "urls": ["https://github.com/settings/tokens"]
    },
    {
        "id": "legit-002",
        "label": 0,
        "category": "Order Confirmation",
        "sender": "auto-confirm@amazon.com",
        "subject": "Your Amazon.com order #114-8937201-9283719 has shipped",
        "text": "Hello Sarah,\n\nYour package containing 'Cybersecurity Architecture & Defense Principles (Hardcover)' is on its way. Estimated delivery date: Thursday, September 18.\n\nYou can track your package progress anytime at https://www.amazon.com/your-orders\n\nThank you for shopping with us.",
        "urls": ["https://www.amazon.com/your-orders"]
    },
    {
        "id": "legit-003",
        "label": 0,
        "category": "Corporate Newsletter",
        "sender": "internal-comms@university.edu",
        "subject": "Campus Weekly Digest - September 2026 Events & Research Seminars",
        "text": "Dear Faculty and Students,\n\nHere is your weekly summary of upcoming campus workshops, academic symposiums, and library operating hours for the coming week. The AI & Cybersecurity symposium will take place this Friday at Hall B.\n\nRead the full event schedule on the university portal: https://www.university.edu/events/september-digest\n\nOffice of Academic Affairs",
        "urls": ["https://www.university.edu/events/september-digest"]
    },
    {
        "id": "legit-004",
        "label": 0,
        "category": "Calendar Invitation",
        "sender": "calendar-notification@google.com",
        "subject": "Invitation: Sprint Planning & Threat Modelling @ Mon Sep 15, 2026 10am - 11am",
        "text": "You have been invited to the following event:\n\nTitle: Sprint Planning & Threat Modelling\nWhen: Monday, Sep 15, 2026, 10:00 AM - 11:00 AM IST\nWhere: Google Meet (meet.google.com/abc-defg-hij)\nOrganizer: lead.architect@enterprise.org\n\nJoin with Google Meet: https://meet.google.com/abc-defg-hij",
        "urls": ["https://meet.google.com/abc-defg-hij"]
    },
    {
        "id": "legit-005",
        "label": 0,
        "category": "Banking Statement",
        "sender": "statements@chase.com",
        "subject": "Your Chase Monthly Account Statement is Ready to View",
        "text": "Dear Customer,\n\nYour monthly statement for account ending in (...4821) is now available online for download. For your security, statements do not include full account numbers.\n\nTo view your statement, log in securely at https://www.chase.com or use the Chase Mobile App.\n\nChase Customer Support",
        "urls": ["https://www.chase.com"]
    },
    {
        "id": "legit-006",
        "label": 0,
        "category": "Software Release",
        "sender": "updates@docker.com",
        "subject": "Docker Desktop 4.35 Release Notes: Performance & Security Enhancements",
        "text": "We are excited to introduce Docker Desktop 4.35! This release brings enhanced build performance, native SBOM generation, and improved resource management for Windows and macOS.\n\nExplore what's new in our documentation at https://docs.docker.com/desktop/release-notes/\n\nHappy Containerizing,\nThe Docker Team",
        "urls": ["https://docs.docker.com/desktop/release-notes/"]
    },
    {
        "id": "legit-007",
        "label": 0,
        "category": "Project Collaboration",
        "sender": "notifications@slack.com",
        "subject": "New direct message from Priya in #cyber-defense-team",
        "text": "Priya sent you a message in Slack:\n\n'Hey, I finished reviewing the threat detection architecture diagram. Everything looks solid for the demo. Let me know when you want to do a quick dry run.'\n\nOpen Slack: https://app.slack.com/client/T0123/C0456",
        "urls": ["https://app.slack.com/client/T0123/C0456"]
    },
    {
        "id": "legit-008",
        "label": 0,
        "category": "Customer Support Ticket",
        "sender": "support@atlassian.com",
        "subject": "[Jira] (SEC-412) Anomaly detection pipeline integration has been updated",
        "text": "David Chen commented on SEC-412:\n\n'Unit tests for the event scoring pipeline have been merged into master branch. Build passing with 98% code coverage.'\n\nView Issue: https://jira.atlassian.net/browse/SEC-412\n\nAtlassian Jira Notifications",
        "urls": ["https://jira.atlassian.net/browse/SEC-412"]
    },
    {
        "id": "legit-009",
        "label": 0,
        "category": "Passwordless Auth Confirmation",
        "sender": "no-reply@auth0.com",
        "subject": "Your one-time login verification link",
        "text": "Hello,\n\nYou requested a magic link to sign in to your developer dashboard. This link was requested from Chrome on Windows (IP: 142.250.190.46).\n\nClick here to sign in: https://login.auth0.com/magic-link?token=9283719283712893\n\nThis link will expire in 10 minutes.",
        "urls": ["https://login.auth0.com/magic-link?token=9283719283712893"]
    },
    {
        "id": "legit-010",
        "label": 0,
        "category": "Cloud Infrastructure Billing",
        "sender": "billing@digitalocean.com",
        "subject": "Invoice for August 2026 - DigitalOcean",
        "text": "Hi Team,\n\nYour invoice for the period August 1 to August 31 is now available. Your credit card on file has been charged $14.20.\n\nYou can review your invoice breakdown and download receipts at: https://cloud.digitalocean.com/billing\n\nThank you for choosing DigitalOcean.",
        "urls": ["https://cloud.digitalocean.com/billing"]
    }
]
