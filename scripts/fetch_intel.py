"""KEV·EPSS 캐시 내려받기. `uv run python scripts/fetch_intel.py` 또는 `uv run triage fetch-intel` 과 같다.

본선 현장 네트워크가 느릴 수 있으니 전날 미리 실행해 두고, 현장에서는 캐시로 동작시킨다.
"""
from triage.cli import app

if __name__ == "__main__":
    app(["fetch-intel"])
