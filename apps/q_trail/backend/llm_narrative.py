"""
Forensic AI Narrative Synthesizer for Q-Trail Circular Loops & Conduits.
Integrates with the unified local AI server at 127.0.0.1:8434/v1/chat/completions
with an ultra-reliable deterministic fallback.
"""

from __future__ import annotations

import json
import logging
import urllib.request
from typing import Any

from django.conf import settings

logger = logging.getLogger(__name__)


def generate_loop_forensic_narrative(loop_data: dict[str, Any]) -> str:
    """
    Generates a concise 2-sentence forensic intelligence synthesis for a detected loop.
    Tries live LLM at settings.LLM_API_ENDPOINT (e.g. http://127.0.0.1:8434/v1/chat/completions)
    and falls back gracefully to a deterministic forensic explanation if unreachable or slow.
    """
    originator = loop_data.get("originator", "Originator")
    counterparty = loop_data.get("counterparty", "Counterparty")
    initial_amt = float(loop_data.get("initial_amount", 0.0))
    return_amt = float(loop_data.get("return_amount", 0.0))
    retained_amt = float(loop_data.get("retained_amount", 0.0))
    conduits = loop_data.get("conduits", [])
    conduits_str = ", ".join(conduits) if conduits else "direct banking channels"
    cycle_nodes = loop_data.get("cycle_nodes", [])
    cycle_str = (
        " → ".join(cycle_nodes) if cycle_nodes else f"{originator} → {counterparty} → {originator}"
    )

    fallback_narrative = (
        f"Capital initiated from '{originator}' (₹{initial_amt:,.2f}) and routed through "
        f"intermediary conduits ({conduits_str}) before returning ₹{return_amt:,.2f} "
        f"back to '{originator}'. A total of ₹{retained_amt:,.2f} was retained in transit fees, "
        f"confirming a closed round-tripping circuit with beneficial control preservation."
    )

    endpoint = getattr(
        settings,
        "TRAIL_LLM_ENDPOINT",
        getattr(settings, "LLM_API_ENDPOINT", "http://127.0.0.1:8434/v1/chat/completions"),
    )
    timeout = float(getattr(settings, "LLM_API_TIMEOUT", 4.0))

    prompt = (
        f"Closed circular round-tripping loop detected in audit:\n"
        f"Path: {cycle_str}\n"
        f"Initial Dispatched Outflow: ₹{initial_amt:,.2f}\n"
        f"Return Inflow: ₹{return_amt:,.2f}\n"
        f"Conduits Withheld Fee: ₹{retained_amt:,.2f}\n"
        f"Intermediaries: {conduits_str}\n\n"
        f"Provide a 2-sentence formal forensic intelligence summary explaining this money laundering/round-tripping scheme and how beneficial control returned to the originator."
    )

    payload = {
        "model": getattr(settings, "LLM_MODEL_NAME", "default"),
        "messages": [
            {
                "role": "system",
                "content": "You are a senior forensic financial intelligence auditor. Respond with exactly two professional, factual sentences.",
            },
            {
                "role": "user",
                "content": prompt,
            },
        ],
        "temperature": 0.2,
        "max_tokens": 120,
    }

    if not (endpoint.startswith("http://") or endpoint.startswith("https://")):
        return fallback_narrative

    try:
        req = urllib.request.Request(
            endpoint,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # nosec B310
            if resp.status == 200:
                result = json.loads(resp.read().decode("utf-8"))
                choices = result.get("choices", [])
                if choices:
                    content = choices[0].get("message", {}).get("content", "").strip()
                    if content:
                        return content
    except Exception as exc:
        logger.debug(f"Local LLM synthesis bypassed ({exc}); using deterministic narrative.")

    return fallback_narrative
