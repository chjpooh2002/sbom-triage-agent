"""PDF 엔진을 선택하고 완성된 PDF 바이트를 반환한다."""
import os
import shutil
import subprocess
from math import isfinite
from pathlib import Path
from tempfile import TemporaryDirectory
from time import perf_counter


_BROWSER_NAMES = ("msedge", "chrome", "google-chrome", "chromium", "chromium-browser")
_WINDOWS_BROWSERS = (
    ("ProgramFiles(x86)", "Microsoft/Edge/Application/msedge.exe"),
    ("ProgramFiles", "Microsoft/Edge/Application/msedge.exe"),
    ("ProgramFiles", "Google/Chrome/Application/chrome.exe"),
    ("LOCALAPPDATA", "Google/Chrome/Application/chrome.exe"),
)
_UNAVAILABLE = "WeasyPrint 라이브러리와 Edge/Chrome을 찾지 못함"
_DEFAULT_TIMEOUT = 240.0


def _find_browser() -> Path | None:
    configured = os.path.expandvars(os.environ.get("SBOMTRIAGE_PDF_BROWSER", "").strip().strip('"'))
    if configured and (path := shutil.which(configured)):
        return Path(path).resolve()
    if os.name == "nt":
        for variable, relative in _WINDOWS_BROWSERS:
            if root := os.environ.get(variable):
                path = Path(root) / relative
                if path.is_file():
                    return path.resolve()
    for name in _BROWSER_NAMES:
        if path := shutil.which(name):
            return Path(path).resolve()
    return None


def _render_weasyprint(page: str) -> bytes:
    from weasyprint import HTML
    from weasyprint.text.fonts import FontConfiguration
    from weasyprint.urls import URLFetcher

    fetcher = URLFetcher(allowed_protocols={"file"})
    return HTML(string=page, url_fetcher=fetcher).write_pdf(font_config=FontConfiguration())


def _browser_timeout() -> float:
    try:
        timeout = float(os.environ.get("SBOMTRIAGE_PDF_TIMEOUT", str(_DEFAULT_TIMEOUT)))
    except ValueError:
        return _DEFAULT_TIMEOUT
    return timeout if isfinite(timeout) and timeout > 0 else _DEFAULT_TIMEOUT


def _print_chromium(page: str, browser: Path) -> bytes:
    with TemporaryDirectory(prefix=".triage-pdf-", ignore_cleanup_errors=True) as temporary:
        root = Path(temporary).resolve()
        html = root / "report.html"
        pdf = root / "report.pdf"
        html.write_text(page, encoding="utf-8")
        # 임시 HTML이 저장소의 로컬 글꼴 파일을 읽을 수 있게 한다.
        subprocess.run(
            [
                str(browser),
                "--headless=new",
                "--disable-gpu",
                "--no-first-run",
                "--no-default-browser-check",
                "--disable-sync",
                "--disable-component-update",
                "--disable-features=Translate,MediaRouter",
                "--disable-extensions",
                "--disable-background-networking",
                "--allow-file-access-from-files",
                "--no-pdf-header-footer",
                f"--user-data-dir={root / 'profile'}",
                f"--print-to-pdf={pdf}",
                html.as_uri(),
            ],
            check=True,
            timeout=_browser_timeout(),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        content = pdf.read_bytes()
        if not content.startswith(b"%PDF-"):
            raise OSError("브라우저가 유효한 PDF를 생성하지 못했습니다.")
        return content


def render_with_engine(page: str) -> tuple[bytes, str, dict[str, float]]:
    started = perf_counter()
    try:
        content = _render_weasyprint(page)
    except (ImportError, OSError) as error:
        browser_started = perf_counter()
        weasyprint_seconds = round(browser_started - started, 6)
        browser = _find_browser()
        if browser is None:
            raise OSError(f"{_UNAVAILABLE} ({type(error).__name__})") from None
        try:
            content = _print_chromium(page, browser)
        except (OSError, subprocess.SubprocessError) as error:
            raise OSError(f"{_UNAVAILABLE}. 브라우저 인쇄에 실패했습니다 ({type(error).__name__})") from None
        return content, f"chromium:{browser.name}", {
            "weasyprint_seconds": weasyprint_seconds,
            "browser_seconds": round(perf_counter() - browser_started, 6),
        }
    return content, "weasyprint", {
        "weasyprint_seconds": round(perf_counter() - started, 6),
        "browser_seconds": 0.0,
    }
