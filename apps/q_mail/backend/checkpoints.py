"""
Q-Mail Forensic Checkpoints & Classification Engine
Rule-based matching and classification for forensic audit investigations:
1. Currency mentions (INR, USD, ₹, Lakhs, Crores, etc.)
2. Without CC/BCC (1-on-1 covert communications)
3. Personal Webmail IDs (@gmail.com, @yahoo.com, etc.)
4. Apart from HMIL (external/personal communications)
5. Primary Bank Statements & Alerts (HDFC, SBI, ICICI, Axis, Kotak, etc.)
6. UPI Payments & Receipts (PhonePe, GPay, Paytm, CRED, etc.)
7. Default Keywords (PAYMENT, GIFT, SALARY, TAX, LOAN, CIBIL)
"""

import re
from typing import Any

# Domain definitions
CORPORATE_DOMAINS = {
    "hmil.net",
    "hyundai.com",
    "hyundai-autoever.com",
    "mobis.co.kr",
    "hyundai.co.kr",
    "kia.com",
}

PERSONAL_WEBMAIL_DOMAINS = {
    "gmail.com",
    "yahoo.com",
    "outlook.com",
    "hotmail.com",
    "icloud.com",
    "rediffmail.com",
    "zoho.com",
    "proton.me",
    "protonmail.com",
    "aol.com",
    "ymail.com",
    "live.com",
    "mail.com",
}

PRIMARY_BANK_DOMAINS = {
    "hdfcbank.net",
    "hdfcbank.com",
    "icicibank.com",
    "sbi.co.in",
    "axisbank.com",
    "kotak.com",
    "indusind.com",
    "yesbank.in",
    "canarabank.com",
    "bankofbaroda.co.in",
    "pnb.co.in",
    "rblbank.com",
    "idfcfirstbank.com",
    "unionbankofindia.co.in",
    "federalbank.co.in",
}

PRIMARY_BANK_KEYWORDS = {
    "hdfc",
    "sbi",
    "icici",
    "axis bank",
    "kotak",
    "state bank",
    "bank of baroda",
    "canara bank",
    "netbanking",
    "account statement",
    "neft cr",
    "rtgs cr",
    "imps cr",
}

UPI_DOMAINS = {
    "phonepe.com",
    "google.com",
    "paytm.com",
    "cred.club",
    "razorpay.com",
    "npci.org.in",
    "bhimupi.org.in",
}

UPI_KEYWORDS = {
    "phonepe",
    "gpay",
    "google pay",
    "googlepay",
    "paytm",
    "upi",
    "vpa",
    "bhim",
    "cred",
    "upi ref",
    "upi transaction",
    "upi payment",
    "okaxis",
    "okhdfcbank",
    "oksbi",
    "okicici",
    "yespay",
    "ybl",
    "ibl",
}

DEFAULT_KEYWORDS = ["PAYMENT", "GIFT", "SALARY", "TAX", "LOAN", "CIBIL"]

# Currency Regex Pattern
CURRENCY_PATTERN = re.compile(
    r"(?:[₹$€£]\s*[\d,]+(?:\.\d+)?)"
    r"|(?:\b(?:inr|rs\.?|usd|eur|gbp)\s*[\d,]+(?:\.\d+)?)"
    r"|(?:[\d,]+(?:\.\d+)?\s*(?:lakhs?|crores?|lacs?|cr\.?|inr|usd|eur|dollars?|rupees?))",
    re.IGNORECASE,
)


def extract_domain(email_address: str) -> str:
    """Extracts lowercase domain name from email address string."""
    if not email_address or "@" not in email_address:
        return ""
    clean_email = email_address.split("<")[-1].replace(">", "").strip()
    parts = clean_email.split("@")
    return parts[-1].lower() if len(parts) > 1 else ""


def check_currency(text: str) -> bool:
    """Returns True if currency symbols, amounts or currency words appear in text."""
    if not text:
        return False
    return bool(CURRENCY_PATTERN.search(text))


def check_no_cc_bcc(recipients_cc: list | None, recipients_bcc: list | None) -> bool:
    """Returns True if message has neither CC nor BCC recipients (1-on-1 direct communication)."""
    has_cc = bool(recipients_cc and len(recipients_cc) > 0)
    has_bcc = bool(recipients_bcc and len(recipients_bcc) > 0)
    return not has_cc and not has_bcc


def check_personal_sender(sender_email: str) -> bool:
    """Returns True if sender is from a known personal webmail domain."""
    domain = extract_domain(sender_email)
    return domain in PERSONAL_WEBMAIL_DOMAINS


def check_non_hmil(sender_email: str, recipients_to: list | None = None) -> bool:
    """Returns True if sender is not from a corporate HMIL/Hyundai domain."""
    domain = extract_domain(sender_email)
    if not domain:
        return True
    return domain not in CORPORATE_DOMAINS


def check_primary_bank(sender_email: str, subject: str = "", body: str = "") -> bool:
    """Returns True if email originates from or discusses primary Indian banking institutions."""
    domain = extract_domain(sender_email)
    if domain in PRIMARY_BANK_DOMAINS:
        return True
    combined_text = f"{subject} {body}".lower()
    return any(bk in combined_text for bk in PRIMARY_BANK_KEYWORDS)


def check_upi_payment(sender_email: str, subject: str = "", body: str = "") -> bool:
    """Returns True if email represents a UPI payment alert, receipt, or transaction."""
    domain = extract_domain(sender_email)
    if domain in UPI_DOMAINS:
        return True
    combined_text = f"{subject} {body}".lower()
    return any(uk in combined_text for uk in UPI_KEYWORDS)


def match_default_keywords(text: str) -> list[str]:
    """Returns list of matched default keywords (PAYMENT, GIFT, SALARY, TAX, LOAN, CIBIL)."""
    if not text:
        return []
    upper_text = text.upper()
    return [kw for kw in DEFAULT_KEYWORDS if kw in upper_text]


def evaluate_email_checkpoints(
    email_obj: Any, profile_keywords: list[str] | None = None
) -> dict[str, Any]:
    """
    Evaluates all forensic checkpoints for a given EmailMessage instance.
    Returns boolean flags and matched badges, including profile investigation keywords.
    """
    combined_text = f"{email_obj.subject or ''} {email_obj.body_plain or ''}"
    sender = email_obj.sender_email or ""
    recipients_to = email_obj.recipients_to or []
    recipients_cc = email_obj.recipients_cc or []
    recipients_bcc = email_obj.recipients_bcc or []

    is_currency = check_currency(combined_text)
    is_no_cc_bcc = check_no_cc_bcc(recipients_cc, recipients_bcc)
    is_personal = check_personal_sender(sender)
    is_non_hmil = check_non_hmil(sender, recipients_to)
    is_bank = check_primary_bank(sender, email_obj.subject or "", email_obj.body_plain or "")
    is_upi = check_upi_payment(sender, email_obj.subject or "", email_obj.body_plain or "")
    matched_default_kws = match_default_keywords(combined_text)

    matched_profile_kws = []
    if profile_keywords:
        upper_text = combined_text.upper()
        for kw in profile_keywords:
            clean_kw = kw.strip().upper()
            if clean_kw and clean_kw in upper_text and clean_kw not in matched_profile_kws:
                matched_profile_kws.append(clean_kw)

    badges = []
    if is_currency:
        badges.append({"label": "Currency", "variant": "amber", "icon": "fa-solid fa-coins"})
    if is_no_cc_bcc:
        badges.append({"label": "1-on-1 Direct", "variant": "sky", "icon": "fa-solid fa-lock"})
    if is_personal:
        badges.append(
            {"label": "Personal Mail", "variant": "purple", "icon": "fa-solid fa-envelope"}
        )
    if is_non_hmil:
        badges.append(
            {
                "label": "External / Non-HMIL",
                "variant": "slate",
                "icon": "fa-solid fa-building-slash",
            }
        )
    if is_bank:
        badges.append(
            {"label": "Primary Bank", "variant": "emerald", "icon": "fa-solid fa-building-columns"}
        )
    if is_upi:
        badges.append(
            {"label": "UPI Payment", "variant": "indigo", "icon": "fa-solid fa-mobile-screen"}
        )
    for kw in matched_default_kws:
        badges.append({"label": kw, "variant": "rose", "icon": "fa-solid fa-tag"})
    for kw in matched_profile_kws:
        badges.append(
            {"label": f"Profile: {kw}", "variant": "rose", "icon": "fa-solid fa-bullseye"}
        )

    return {
        "is_currency": is_currency,
        "is_no_cc_bcc": is_no_cc_bcc,
        "is_personal_sender": is_personal,
        "is_non_hmil": is_non_hmil,
        "is_primary_bank": is_bank,
        "is_upi_payment": is_upi,
        "matched_default_keywords": matched_default_kws,
        "matched_profile_keywords": matched_profile_kws,
        "badges": badges,
    }
