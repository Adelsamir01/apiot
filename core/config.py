"""config.py — Environment configuration for APIOT.

Loads .env from the apiot package root and provides strict accessors.
The OpenRouter API key is REQUIRED for the autonomous agent to function.
"""

import os
from pathlib import Path
from dotenv import load_dotenv

_APIOT_ROOT = Path(__file__).resolve().parent.parent
load_dotenv(_APIOT_ROOT / ".env")


def get_openrouter_api_key() -> str | None:
    """Return the API key if set, or None. Used by the CLI for soft checks."""
    key = os.getenv("OPENROUTER_API_KEY", "").strip()
    return key or None


def require_openrouter_api_key() -> str:
    """Return the API key or raise SystemExit. Used by the agent directly."""
    key = get_openrouter_api_key()
    if not key:
        raise SystemExit(
            "[APIOT] OPENROUTER_API_KEY is not set.\n"
            "The autonomous agent requires a valid API key to function.\n"
            "Run 'apiot' for interactive setup, or set it in apiot/.env:\n"
            '  OPENROUTER_API_KEY="sk-or-v1-..."'
        )
    return key


def get_llm_model() -> str:
    """Return the LLM model identifier. Defaults to Anthropic Claude 3.5 Sonnet."""
    return os.getenv("LLM_MODEL", "anthropic/claude-3.5-sonnet")
