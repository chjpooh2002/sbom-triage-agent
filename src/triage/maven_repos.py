"""POM과 버전 메타데이터에 공통으로 적용하는 Maven 저장소 조회."""
import os
from collections import Counter
from importlib.metadata import version
from random import uniform
from time import sleep
from urllib.parse import urlsplit
from xml.etree.ElementTree import ParseError
from xml.parsers.expat import ExpatError

import httpx

CENTRAL = "https://repo.maven.apache.org/maven2"
DEFAULT_REPOS = (
    "https://maven-central-asia.storage-download.googleapis.com/maven2",
    "https://maven-central.storage-download.googleapis.com/maven2",
    CENTRAL,
)
RETRY_DELAYS = (0.5, 1.0, 2.0)
USER_AGENT = f"sbom-triage-agent/{version('triage')} (+https://github.com/chjpooh2002/sbom-triage-agent)"


def repositories():
    configured = os.environ.get("SBOMTRIAGE_MAVEN_REPOS", "")
    repos = tuple(dict.fromkeys(item.strip().rstrip("/") for item in configured.split(",") if item.strip()))
    for repo in repos:
        url = urlsplit(repo)
        if url.scheme not in {"http", "https"} or not url.hostname or url.username or url.password or url.query or url.fragment:
            raise ValueError("SBOMTRIAGE_MAVEN_REPOS에 유효한 HTTP(S) 저장소 주소가 필요합니다.")
    return repos or DEFAULT_REPOS


def download(url):
    return httpx.get(url, timeout=httpx.Timeout(15.0, connect=5.0),
                     headers={"User-Agent": USER_AGENT}, follow_redirects=True)


class FetchError(Exception):
    def __init__(self, results):
        self.summary = " / ".join(f"{repo} {outcome}" for repo, outcome in results.items())
        self.missing = all(outcome == "HTTP 404" for outcome in results.values())
        super().__init__(self.summary)


class MavenRepositories:
    def __init__(self):
        self.repos = repositories()
        self.blocks = Counter()

    def fetch(self, path, request, parse, event=None):
        results = {}
        for repo in sorted(self.repos, key=lambda repo: self.blocks[repo] >= 3):
            url = f"{repo}/{path}"
            for attempt in range(1, len(RETRY_DELAYS) + 2):
                status = None
                error = None
                blocked = retry = False
                try:
                    if event:
                        event("maven.fetch", url=url, repository=repo, attempt=attempt)
                    response = request(url)
                    status = response.status_code
                    if 200 <= status < 300:
                        return parse(response.content.decode("utf-8-sig"), url)
                    blocked = status in {403, 429} or (
                        status == 404 and (not response.content.strip() or
                                           "xml" not in response.headers.get("content-type", "").lower()))
                    retry = 500 <= status < 600
                except httpx.RequestError as exc:
                    error = type(exc).__name__
                    retry = isinstance(exc, (httpx.TimeoutException, httpx.NetworkError, httpx.ProxyError))
                except (OSError, ValueError, ExpatError, ParseError) as exc:
                    error = type(exc).__name__

                outcome = error or f"HTTP {status}"
                results[repo] = outcome + (" (막힘)" if blocked else "")
                if event:
                    event("maven.fetch_error", repository=repo, attempt=attempt,
                          status_code=status, error_type=error, blocked=blocked)
                if blocked:
                    self.blocks[repo] += 1
                if blocked or not retry or attempt > len(RETRY_DELAYS):
                    break
                delay = RETRY_DELAYS[attempt - 1]
                sleep(delay + uniform(0, delay / 4))
        raise FetchError(results)
