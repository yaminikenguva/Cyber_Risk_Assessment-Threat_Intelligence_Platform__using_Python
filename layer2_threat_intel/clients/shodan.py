import requests
from typing import Dict, Any

SHODAN_API_URL = "https://api.shodan.io/shodan/host/"

def lookup_shodan(ip: str, api_key: str) -> Dict[str, Any]:
    try:
        r = requests.get(
            f"{SHODAN_API_URL}{ip}",
            params={"key": api_key},
            timeout=10
        )
        if r.ok:
            return r.json()
    except Exception:
        pass

    return {}
