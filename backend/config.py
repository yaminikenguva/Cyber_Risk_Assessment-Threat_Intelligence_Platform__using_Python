# Load API keys (.env)

import os
from pathlib import Path
from dotenv import load_dotenv

# Load .env from project root
BASE_DIR = Path(__file__).resolve().parents[1]
load_dotenv(BASE_DIR / ".env")

VULNERS_API_KEY = os.getenv("VULNERS_API_KEY")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")
NVD_API_KEY = os.getenv("NVD_API_KEY")


def validate_config():
    warnings = []

    if not VULNERS_API_KEY:
        warnings.append("VULNERS_API_KEY missing")
    if not VIRUSTOTAL_API_KEY:
        warnings.append("VIRUSTOTAL_API_KEY missing")
    if not SHODAN_API_KEY:
        warnings.append("SHODAN_API_KEY missing")
    if not NVD_API_KEY:
        warnings.append("NVD_API_KEY missing")

    return warnings
