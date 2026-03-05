import os
from pathlib import Path
from dotenv import load_dotenv

# Load .env from the apiot package root (apiot/.env), regardless of cwd
_APIOT_ROOT = Path(__file__).resolve().parent.parent
load_dotenv(_APIOT_ROOT / ".env")

def get_openrouter_api_key() -> str:
    """Retrieves the OpenRouter API Key from the environment."""
    key = os.getenv("OPENROUTER_API_KEY")
    if not key:
        raise ValueError(
            "OPENROUTER_API_KEY is missing. "
            "Please ensure it is set in your environment or present in a local .env file."
        )
    return key

def get_llm_model() -> str:
    """Retrieves the LLM Model identifier from the environment. Defaults to Anthropic."""
    return os.getenv("LLM_MODEL", "anthropic/claude-3.5-sonnet")
