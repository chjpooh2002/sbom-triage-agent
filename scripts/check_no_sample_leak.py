"""샘플 지식 하드코딩 검사: data/field/ 샘플의 고유 식별자나 취약점 ID가 src/·config/에 있으면 실패.
사용: uv run python scripts/check_no_sample_leak.py
"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
field = ROOT / "data" / "field"
if not field.exists():
    print("data/field 없음: 검사 생략"); sys.exit(0)
common = {"__init__", "readme", "config", "settings", "server", "dockerfile", "package", "requirements",
          "application", "pom", "preview", "generated", "vendor", "templates", "auth", "store", "public", "admin", "partner", "index", "app", "smoke", "test"}
words = {p.stem for p in field.rglob("*") if p.is_file()}
words = {w for w in words if len(w) >= 6 and w.lower() not in common}
words |= {d.name for d in field.iterdir() if d.is_dir()}
cve = re.compile(r"\b(CVE-\d{4}-\d{4,}|GHSA(?:-[0-9a-z]{4}){3})\b")
bad = []
for base in ("src", "config"):
    for f in (ROOT / base).rglob("*"):
        if f.suffix not in {".py", ".yaml", ".yml", ".txt", ".md", ".j2", ".html", ".json"}:
            continue
        t = f.read_text(encoding="utf-8", errors="ignore")
        bad += [f"{f.relative_to(ROOT)}: 샘플 식별자 '{w}'" for w in words if re.search(rf"\b{re.escape(w)}\b", t)]
        bad += [f"{f.relative_to(ROOT)}: 취약점 ID '{m}'" for m in cve.findall(t)]
print("\n".join(bad) or "통과: 샘플 지식 하드코딩 없음")
sys.exit(1 if bad else 0)
