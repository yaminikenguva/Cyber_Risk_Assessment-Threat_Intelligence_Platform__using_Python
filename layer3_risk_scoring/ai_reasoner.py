# AI explanations

import os
import json
import requests
from typing import Dict, Any, List
from dotenv import load_dotenv

# ===============================
# ENV CONFIG
# ===============================
load_dotenv()

OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY")
OPENROUTER_ENDPOINT = "https://openrouter.ai/api/v1/chat/completions"
MODEL_NAME = "openai/gpt-4o-mini"

AI_TIMEOUT = 25  # seconds


# ===============================
# SAFETY CHECK
# ===============================
def _ai_enabled() -> bool:
    return bool(OPENROUTER_API_KEY)


# ===============================
# PROMPT BUILDER
# ===============================
def _build_prompt(risk_data: Dict[str, Any], question: str | None) -> str:
    return f"""
You are a senior cybersecurity risk analyst.

You are given risk-scored vulnerability assessment data from an enterprise security platform.

Data:
{json.dumps(risk_data, indent=2)}

Task:
- Explain risks clearly
- Identify critical assets
- Suggest remediation priorities
- Avoid jargon unless necessary
- Keep responses professional and concise

User Question:
{question or "Summarize the key risks and recommended actions."}
"""


# ===============================
# AI CORE FUNCTION (BACKEND SAFE)
# ===============================
def generate_ai_analysis(
    layer3_results: Dict[str, Any],
    user_question: str | None = None
) -> Dict[str, Any]:
    """
    Entry point for AI reasoning.

    Input:
      - layer3_results (DICT from scorer.py)
      - optional user question

    Output:
      {
        "enabled": bool,
        "analysis": str,
        "model": str
      }
    """

    if not _ai_enabled():
        return {
            "enabled": False,
            "analysis": "AI analysis is disabled (missing API key).",
            "model": None
        }

    prompt = _build_prompt(layer3_results, user_question)

    headers = {
        "Authorization": f"Bearer {OPENROUTER_API_KEY}",
        "Content-Type": "application/json",
        "HTTP-Referer": "http://localhost",
        "X-Title": "CRATIP AI Analyst"
    }

    payload = {
        "model": MODEL_NAME,
        "messages": [
            {"role": "system", "content": "You are a cybersecurity risk expert."},
            {"role": "user", "content": prompt}
        ],
        "temperature": 0.4
    }

    try:
        r = requests.post(
            OPENROUTER_ENDPOINT,
            headers=headers,
            json=payload,
            timeout=AI_TIMEOUT
        )
        r.raise_for_status()

        answer = r.json()["choices"][0]["message"]["content"]

        return {
            "enabled": True,
            "analysis": answer,
            "model": MODEL_NAME
        }

    except Exception as e:
        return {
            "enabled": True,
            "analysis": f"AI analysis failed: {str(e)}",
            "model": MODEL_NAME
        }
