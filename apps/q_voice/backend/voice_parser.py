"""
Q-Voice Transcript Parser & Diarization Intent Screener
Parses audio metadata, WebVTT (.vtt), SRT (.srt), JSON/CSV call transcripts, and plain diarized transcripts.
"""

import json
import re
from pathlib import Path
from typing import Any

DEFAULT_VOICE_INTENTS = [
    (
        "Collusion",
        [
            ("kickback", 95),
            ("commission", 65),
            ("cut", 50),
            ("bribe", 95),
            ("cash payment", 85),
            ("hawala", 90),
            ("off the record", 80),
            ("secret deal", 85),
            ("inside info", 90),
            ("win the tender", 75),
        ],
    ),
    (
        "Concealment",
        [
            ("dont email", 85),
            ("delete the message", 85),
            ("burn this", 90),
            ("dont tell anyone", 80),
            ("keep it quiet", 75),
            ("call on personal phone", 75),
            ("no paper trail", 90),
        ],
    ),
    (
        "Price Negotiation",
        [
            ("quote", 40),
            ("discount", 45),
            ("margin", 45),
            ("l1 price", 65),
            ("lower the bid", 60),
            ("rates", 35),
        ],
    ),
    (
        "Pressure",
        [
            ("cancel contract", 70),
            ("blacklist", 75),
            ("do as i say", 80),
            ("last chance", 65),
        ],
    ),
    (
        "Procurement",
        [
            ("rfq", 40),
            ("vendor", 30),
            ("supplier", 30),
            ("specification", 35),
            ("po number", 50),
            ("purchase order", 45),
        ],
    ),
]

IDENTITIES_KEYWORDS = {
    "saravan",
    "kumar",
    "indumadhi",
    "indhumadhi",
    "indhumathi",
    "design",
    "hr",
    "metec",
    "arun",
    "rajesh",
    "boss",
    "manager",
    "vendor",
    "client",
    "supervisor",
    "officer",
    "buyer",
    "supplier",
    "lead",
}

FINANCIAL_KEYWORDS = {
    "sbi",
    "icici",
    "hdfc",
    "axis",
    "canara",
    "thousand",
    "lakh",
    "crore",
    "rupees",
    "upa",
    "upi",
    "gpay",
    "phonepe",
    "paytm",
    "transfer",
    "bank account",
    "cac",
    "transaction",
    "inquiry",
    "november",
    "25,000",
    "25000",
    "50,000",
    "commission",
    "cash",
    "cut",
    "discount",
    "margin",
    "quote",
    "rate",
    "remit",
    "payment",
    "tender",
    "rfq",
}

SUSPICIOUS_KEYWORDS = {
    "bribe",
    "kickback",
    "hawala",
    "dont email",
    "do not email",
    "delete the message",
    "delete",
    "burn this",
    "burn",
    "dont tell anyone",
    "keep it quiet",
    "call on personal phone",
    "off the record",
    "no paper trail",
    "secret deal",
    "inside info",
    "blacklist",
    "cancel contract",
    "collusion",
    "clear chat",
    "personal account",
}


def tag_transcript_detections(
    text: str, extra_keywords: list[str] | None = None
) -> list[dict[str, str]]:
    """
    Tags hotwords and entities in a transcript line with appropriate classification types.
    Types: 'identity' (p-tag), 'financial' (f-tag), 'suspicious' (s-tag), 'profile' (investigation).
    """
    if not text:
        return []

    text_lower = text.lower()
    detections: list[dict[str, str]] = []
    seen: set[str] = set()

    for kw in SUSPICIOUS_KEYWORDS:
        if re.search(r"\b" + re.escape(kw) + r"\b", text_lower) and kw not in seen:
            seen.add(kw)
            detections.append({"term": kw.upper(), "type": "suspicious", "category": "Suspicious"})

    for kw in FINANCIAL_KEYWORDS:
        if re.search(r"\b" + re.escape(kw) + r"\b", text_lower) and kw not in seen:
            seen.add(kw)
            detections.append({"term": kw.upper(), "type": "financial", "category": "Financial"})

    for kw in IDENTITIES_KEYWORDS:
        if re.search(r"\b" + re.escape(kw) + r"\b", text_lower) and kw not in seen:
            seen.add(kw)
            detections.append({"term": kw.upper(), "type": "identity", "category": "Identity"})

    if extra_keywords:
        for kw in extra_keywords:
            kw_clean = kw.strip().lower()
            if kw_clean and kw_clean not in seen:
                if re.search(r"\b" + re.escape(kw_clean) + r"\b", text_lower):
                    seen.add(kw_clean)
                    detections.append(
                        {
                            "term": kw.upper(),
                            "type": "profile",
                            "category": "Profile Keyword",
                        }
                    )

    return detections


def extract_speaker_and_text(raw_text: str, default_speaker: str = "") -> tuple[str, str]:
    """
    Extracts speaker identifier and cleaned utterance from transcript text.
    """
    if not raw_text:
        return default_speaker, ""

    v_tag = re.match(r"^<v\s+([^>]+)>(.*?)(?:</v>)?$", raw_text, re.IGNORECASE)
    if v_tag:
        return v_tag.group(1).strip(), v_tag.group(2).strip()

    b_tag = re.match(r"^\[([^\]]+)\]:?\s*(.*)$", raw_text)
    if b_tag:
        return b_tag.group(1).strip(), b_tag.group(2).strip()

    c_tag = re.match(r"^(Speaker\s*\d+(?:\s*\([^)]+\))?|[A-Z][a-zA-Z\s]{1,25}):\s+(.*)$", raw_text)
    if c_tag:
        return c_tag.group(1).strip(), c_tag.group(2).strip()

    return default_speaker, raw_text.strip()


def screen_text_for_intent(
    text: str, extra_keywords: list[str] | None = None
) -> tuple[str, list[str], int]:
    """
    Screens an utterance against intent patterns and returns (intent, flagged_keywords, risk_score).
    """
    if not text:
        return "General", [], 0

    text_lower = text.lower()
    highest_intent = "General"
    max_risk = 0
    flagged: list[str] = []

    for intent, kw_list in DEFAULT_VOICE_INTENTS:
        for kw, weight in kw_list:
            if re.search(r"\b" + re.escape(kw) + r"\b", text_lower):
                flagged.append(kw.upper())
                if weight > max_risk:
                    max_risk = weight
                    highest_intent = intent

    if extra_keywords:
        for kw in extra_keywords:
            kw_clean = kw.strip().lower()
            if kw_clean and re.search(r"\b" + re.escape(kw_clean) + r"\b", text_lower):
                flagged.append(kw.upper())
                if max_risk < 35:
                    max_risk = 35
                if highest_intent == "General":
                    highest_intent = "Profile Keyword Hit"

    return highest_intent, list(set(flagged)), max_risk


def parse_transcript_text_to_timeline(
    raw_content: str, extra_keywords: list[str] | None = None
) -> list[dict[str, Any]]:
    """
    Converts raw text/VTT/SRT transcript into standardized timeline chunks with speaker separation.
    """
    lines = raw_content.splitlines()
    timeline: list[dict[str, Any]] = []

    pat_interval = re.compile(
        r"(\d{1,2}:\d{2}(?::\d{2})?(?:\.\d+)?)\s*-->\s*(\d{1,2}:\d{2}(?::\d{2})?(?:\.\d+)?)"
    )
    pat_inline = re.compile(r"^\[?(\d{1,2}:\d{2}(?::\d{2})?)\]?\s*(.*)$")

    pending_interval = ""
    speaker_turn_idx = 0
    for line in lines:
        line_clean = line.strip()
        if not line_clean or line_clean.startswith("WEBVTT") or line_clean.isdigit():
            continue

        m_int = pat_interval.search(line_clean)
        if m_int:
            s_time = m_int.group(1).split(".")[0]
            e_time = m_int.group(2).split(".")[0]
            if s_time.count(":") == 1:
                s_time = f"00:{s_time}"
            if e_time.count(":") == 1:
                e_time = f"00:{e_time}"
            pending_interval = f"[{s_time} --> {e_time}]"
            continue

        if pending_interval:
            default_spk = f"Speaker {(speaker_turn_idx % 2) + 1}"
            speaker, clean_text = extract_speaker_and_text(line_clean, default_spk)
            dets = tag_transcript_detections(clean_text, extra_keywords=extra_keywords)
            intent, flagged_kw, risk = screen_text_for_intent(
                clean_text, extra_keywords=extra_keywords
            )
            timeline.append(
                {
                    "timestamp": pending_interval,
                    "transcript": clean_text,
                    "speaker": speaker,
                    "detections": [d["term"] for d in dets],
                    "detections_detail": dets,
                    "intent": intent,
                    "risk_score": risk,
                }
            )
            pending_interval = ""
            speaker_turn_idx += 1
            continue

        m_inline = pat_inline.match(line_clean)
        if m_inline and m_inline.group(1):
            t_str = m_inline.group(1)
            text_part = m_inline.group(2)
            parts = t_str.split(":")
            if len(parts) == 3:
                s_sec = int(parts[0]) * 3600 + int(parts[1]) * 60 + int(parts[2])
            elif len(parts) == 2:
                s_sec = int(parts[0]) * 60 + int(parts[1])
            else:
                s_sec = 0
            e_sec = s_sec + 5
            s_fmt = f"{s_sec // 3600:02d}:{(s_sec % 3600) // 60:02d}:{s_sec % 60:02d}"
            e_fmt = f"{e_sec // 3600:02d}:{(e_sec % 3600) // 60:02d}:{e_sec % 60:02d}"
            ts_label = f"[{s_fmt} --> {e_fmt}]"
            default_spk = f"Speaker {(speaker_turn_idx % 2) + 1}"
            speaker, clean_text = extract_speaker_and_text(text_part, default_spk)
            dets = tag_transcript_detections(clean_text, extra_keywords=extra_keywords)
            intent, flagged_kw, risk = screen_text_for_intent(
                clean_text, extra_keywords=extra_keywords
            )
            timeline.append(
                {
                    "timestamp": ts_label,
                    "transcript": clean_text,
                    "speaker": speaker,
                    "detections": [d["term"] for d in dets],
                    "detections_detail": dets,
                    "intent": intent,
                    "risk_score": risk,
                }
            )
            speaker_turn_idx += 1

    return timeline


def ingest_transcript_content(
    content: str, filename: str, extra_keywords: list[str] | None = None
) -> list[dict[str, Any]]:
    """
    Ingests raw file text and produces structured diarization segment dictionaries.
    """
    ext = Path(filename).suffix.lower()
    if ext == ".json":
        try:
            data = json.loads(content)
            if isinstance(data, list):
                return data
            if isinstance(data, dict) and "timeline_transcript" in data:
                return data["timeline_transcript"]
        except (json.JSONDecodeError, KeyError, TypeError, ValueError):
            return parse_transcript_text_to_timeline(content, extra_keywords=extra_keywords)

    return parse_transcript_text_to_timeline(content, extra_keywords=extra_keywords)
