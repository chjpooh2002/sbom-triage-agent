"""PDF 엔진을 선택하고 완성된 PDF 바이트를 반환한다."""
import os
import shutil
import subprocess
from pathlib import Path
from tempfile import TemporaryDirectory


_BROWSER_NAMES = ("msedge", "chrome", "google-chrome", "chromium", "chromium-browser")
_WINDOWS_BROWSERS = (
    ("ProgramFiles(x86)", "Microsoft/Edge/Application/msedge.exe"),
    ("ProgramFiles", "Microsoft/Edge/Application/msedge.exe"),
    ("ProgramFiles", "Google/Chrome/Application/chrome.exe"),
    ("LOCALAPPDATA", "Google/Chrome/Application/chrome.exe"),
)
_UNAVAILABLE = "WeasyPrint 라이브러리와 Edge/Chrome을 찾지 못함"


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


def _print_chromium(page: str, browser: Path, directory: Path) -> bytes:
    with TemporaryDirectory(prefix=".triage-pdf-", dir=directory) as temporary:
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
                "--disable-extensions",
                "--disable-background-networking",
                "--allow-file-access-from-files",
                "--no-pdf-header-footer",
                f"--user-data-dir={root / 'profile'}",
                f"--print-to-pdf={pdf}",
                html.as_uri(),
            ],
            check=True,
            timeout=120,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        content = pdf.read_bytes()
        if not content.startswith(b"%PDF-"):
            raise OSError("브라우저가 유효한 PDF를 생성하지 못했습니다.")
        return content


def render_with_engine(page: str, directory: Path) -> tuple[bytes, str]:
    try:
        return _render_weasyprint(page), "weasyprint"
    except (ImportError, OSError):
        browser = _find_browser()
        if browser is None:
            raise OSError(_UNAVAILABLE) from None
        directory.mkdir(parents=True, exist_ok=True)
        try:
            return _print_chromium(page, browser, directory), f"chromium:{browser.name}"
        except (OSError, subprocess.SubprocessError):
            raise OSError(f"{_UNAVAILABLE}. 브라우저 인쇄에 실패했습니다.") from None
