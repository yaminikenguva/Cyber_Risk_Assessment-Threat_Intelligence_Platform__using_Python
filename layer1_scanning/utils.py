import os
from datetime import datetime
from typing import List


# =================================================
# NMAP CONFIGURATION
# =================================================
# MUST remain a list (used with *NMAP_ARGUMENTS)
NMAP_ARGUMENTS: List[str] = [
    "-sT",                 # TCP connect (Windows-safe)
    "-Pn",                 # Skip host discovery
    "-sV",                 # Service version detection
    "--open",              # Show only open ports
    "-T4",                 # Faster timing
    "--script", "vulners", # CVE-based vuln detection
    "--host-timeout", "5m",
    "--max-retries", "2"
]


# =================================================
# LOGGING UTILITY (BACKEND SAFE)
# =================================================
def log(message: str, level: str = "INFO") -> None:
    """
    Lightweight structured logger.
    Safe for FastAPI background tasks.
    NEVER raises exceptions.
    """
    try:
        timestamp = datetime.utcnow().isoformat()
        print(f"[{timestamp}] [{level}] {message}", flush=True)
    except Exception:
        # Absolute safety: logging must NEVER break scans
        pass


# =================================================
# FILENAME SANITIZATION (OPTIONAL USE)
# =================================================
def sanitize_filename(name: str) -> str:
    """
    Convert a target string into a filesystem-safe filename.
    (Used only if file-based exports are added later)
    """
    if not name:
        return "unknown_target"

    return (
        name.replace("https://", "")
        .replace("http://", "")
        .replace("/", "_")
        .replace("\\", "_")
        .replace(":", "_")
        .replace("?", "_")
        .replace("&", "_")
        .strip()
    )


# =================================================
# OPTIONAL: RESULTS FOLDER (NOT USED BY DEFAULT)
# =================================================
def ensure_results_folder() -> str:
    """
    OPTIONAL utility.
    Not required for DB-based pipeline.
    Kept only for future file export support.
    """
    base_dir = os.path.dirname(os.path.abspath(__file__))
    results_dir = os.path.join(base_dir, "results")
    os.makedirs(results_dir, exist_ok=True)
    return results_dir
