#!/usr/bin/env python3

"""
PhishGuard v2.4
Layered phishing detection build.

Detection order:
1. Local verified-phishing threat-intelligence cache
2. Host-level threat-intelligence comparison
3. Existing PhishGuard v2.3 heuristic analysis
4. Existing TLS analysis
5. BLOCK / WARN / ALLOW decision

The browser UI remains inherited from the existing PhishGuard application.
"""

import csv
import hashlib
import os
import time
import urllib.parse
import urllib.request
from pathlib import Path

import phishguard_v22 as pg
import phishguard_v23 as v23


BASE = Path(__file__).resolve().parent

CACHE_DIR = BASE / "threat_intel"
CACHE_DIR.mkdir(exist_ok=True)

PHISHTANK_CACHE = CACHE_DIR / "phishtank_verified.csv"
OPENPHISH_CACHE = CACHE_DIR / "openphish.txt"

CACHE_MAX_AGE_SECONDS = 60 * 60

USER_AGENT = (
    "PhishGuard-DEng-Research/2.4 "
    "academic-phishing-detection"
)


def normalize_url(url):
    """
    Normalize a URL for comparison without visiting it.
    """

    url = (url or "").strip()

    if not url:
        return ""

    if "://" not in url:
        url = "https://" + url

    try:
        parsed = urllib.parse.urlsplit(url)
    except Exception:
        return url.lower()

    scheme = (parsed.scheme or "https").lower()
    host = (parsed.hostname or "").lower().rstrip(".")

    port = parsed.port

    netloc = host

    if port:
        if not (
            (scheme == "https" and port == 443)
            or (scheme == "http" and port == 80)
        ):
            netloc = f"{host}:{port}"

    path = parsed.path or "/"

    while "//" in path:
        path = path.replace("//", "/")

    query = parsed.query or ""

    return urllib.parse.urlunsplit(
        (
            scheme,
            netloc,
            path,
            query,
            ""
        )
    )


def extract_host(url):
    try:
        if "://" not in url:
            url = "https://" + url

        return (
            urllib.parse.urlsplit(url)
            .hostname
            or ""
        ).lower().rstrip(".")

    except Exception:
        return ""


def cache_is_fresh(path):
    if not path.exists():
        return False

    age = time.time() - path.stat().st_mtime

    return age < CACHE_MAX_AGE_SECONDS


def download_file(url, destination):
    """
    Downloads threat intelligence only.
    Does NOT navigate to any phishing URL contained in the feed.
    """

    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": USER_AGENT
        }
    )

    with urllib.request.urlopen(
        request,
        timeout=30
    ) as response:

        data = response.read()

    temp = destination.with_suffix(
        destination.suffix + ".tmp"
    )

    temp.write_bytes(data)

    temp.replace(destination)


def update_phishtank():
    """
    Downloads PhishTank's verified-online CSV.

    PhishTank recommends an application key for automated use.
    If PHISHTANK_APP_KEY exists in the environment, use it.
    """

    if cache_is_fresh(PHISHTANK_CACHE):
        return True

    app_key = os.environ.get(
        "PHISHTANK_APP_KEY",
        ""
    ).strip()

    if app_key:
        url = (
            "http://data.phishtank.com/data/"
            f"{app_key}/online-valid.csv"
        )
    else:
        url = (
            "http://data.phishtank.com/data/"
            "online-valid.csv"
        )

    try:
        print(
            "PhishGuard: updating PhishTank "
            "verified-phishing cache..."
        )

        download_file(
            url,
            PHISHTANK_CACHE
        )

        print(
            "PhishGuard: PhishTank cache updated."
        )

        return True

    except Exception as exc:

        print(
            "PhishGuard: PhishTank update unavailable:",
            exc
        )

        return PHISHTANK_CACHE.exists()


def update_openphish():
    """
    Attempts to update the OpenPhish Community feed.

    Failure does not prevent PhishGuard from running.
    """

    if cache_is_fresh(OPENPHISH_CACHE):
        return True

    urls = [
        "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt",
        "https://openphish.com/feed.txt"
    ]

    for url in urls:

        try:
            print(
                "PhishGuard: updating OpenPhish cache..."
            )

            download_file(
                url,
                OPENPHISH_CACHE
            )

            print(
                "PhishGuard: OpenPhish cache updated."
            )

            return True

        except Exception:
            continue

    print(
        "PhishGuard: OpenPhish update unavailable. "
        "Existing cache will be used if present."
    )

    return OPENPHISH_CACHE.exists()


class ThreatIntelEngine:

    def __init__(self):

        self.urls = set()
        self.hosts = set()

        self.url_sources = {}

        self.load()

    def add_entry(self, url, source):

        normalized = normalize_url(url)

        if not normalized:
            return

        host = extract_host(normalized)

        self.urls.add(normalized)

        self.url_sources[
            normalized
        ] = source

        if host:
            self.hosts.add(host)

    def load_phishtank(self):

        if not PHISHTANK_CACHE.exists():
            return

        try:
            with PHISHTANK_CACHE.open(
                "r",
                newline="",
                encoding="utf-8-sig",
                errors="replace"
            ) as f:

                reader = csv.DictReader(f)

                for row in reader:

                    verified = (
                        row.get("verified", "")
                        .strip()
                        .lower()
                    )

                    online = (
                        row.get("online", "")
                        .strip()
                        .lower()
                    )

                    url = (
                        row.get("url", "")
                        .strip()
                    )

                    if (
                        url
                        and verified == "yes"
                        and online == "yes"
                    ):
                        self.add_entry(
                            url,
                            "PhishTank"
                        )

        except Exception as exc:

            print(
                "PhishGuard: unable to parse "
                "PhishTank cache:",
                exc
            )

    def load_openphish(self):

        if not OPENPHISH_CACHE.exists():
            return

        try:
            with OPENPHISH_CACHE.open(
                "r",
                encoding="utf-8",
                errors="replace"
            ) as f:

                for line in f:

                    url = line.strip()

                    if (
                        url
                        and not url.startswith("#")
                    ):
                        self.add_entry(
                            url,
                            "OpenPhish"
                        )

        except Exception as exc:

            print(
                "PhishGuard: unable to parse "
                "OpenPhish cache:",
                exc
            )

    def load(self):

        update_phishtank()
        update_openphish()

        self.load_phishtank()
        self.load_openphish()

        print(
            "PhishGuard threat intelligence loaded:"
        )

        print(
            f"  Known phishing URLs: {len(self.urls):,}"
        )

        print(
            f"  Known phishing hosts: {len(self.hosts):,}"
        )

    def check(self, url):

        normalized = normalize_url(url)
        host = extract_host(url)

        if not normalized:
            return {
                "matched": False,
                "match_type": None,
                "source": None
            }

        #
        # Exact normalized URL match
        #
        if normalized in self.urls:

            return {
                "matched": True,
                "match_type": "EXACT_URL",
                "source":
                    self.url_sources.get(
                        normalized,
                        "Threat intelligence"
                    )
            }

        #
        # Try http/https counterpart
        #
        try:
            parsed = urllib.parse.urlsplit(
                normalized
            )

            opposite = (
                "http"
                if parsed.scheme == "https"
                else "https"
            )

            alternate = (
                urllib.parse.urlunsplit(
                    (
                        opposite,
                        parsed.netloc,
                        parsed.path,
                        parsed.query,
                        ""
                    )
                )
            )

            if alternate in self.urls:

                return {
                    "matched": True,
                    "match_type":
                        "NORMALIZED_URL",
                    "source":
                        self.url_sources.get(
                            alternate,
                            "Threat intelligence"
                        )
                }

        except Exception:
            pass

        #
        # Host-level match
        #
        if host and host in self.hosts:

            return {
                "matched": True,
                "match_type": "HOST",
                "source": "Threat intelligence"
            }

        return {
            "matched": False,
            "match_type": None,
            "source": None
        }


THREAT_INTEL = ThreatIntelEngine()


class PhishGuardV24Engine:

    def __init__(self):

        self.local_engine = (
            v23.EnhancedPhishGuardEngine()
        )

        if hasattr(
            self.local_engine,
            "tls_engine"
        ):
            self.tls_engine = (
                self.local_engine.tls_engine
            )

    def analyze(self, url):

        #
        # Layer 1: known phishing intelligence
        #
        intelligence = THREAT_INTEL.check(url)

        #
        # Layer 2: normal PhishGuard analysis
        #
        if hasattr(self, "tls_engine"):

            try:
                self.local_engine.tls_engine = (
                    self.tls_engine
                )
            except Exception:
                pass

        verdict = (
            self.local_engine.analyze(url)
        )

        #
        # A verified threat-intelligence match is
        # sufficient to BLOCK.
        #
        if intelligence["matched"]:

            source = (
                intelligence["source"]
                or "independent threat intelligence"
            )

            match_type = (
                intelligence["match_type"]
            )

            if match_type == "EXACT_URL":

                explanation = (
                    "This exact website address appears "
                    f"in the {source} verified phishing "
                    "intelligence data."
                )

            elif match_type == "NORMALIZED_URL":

                explanation = (
                    "A normalized form of this website "
                    f"appears in {source} verified "
                    "phishing intelligence."
                )

            else:

                explanation = (
                    "This website host appears in current "
                    "phishing threat intelligence."
                )

            pg.added_by_v24 = True

            try:
                verdict.evidence.append(
                    pg.EvidenceItem(
                        category=
                            "Threat Intelligence",
                        test_name=
                            "Known phishing intelligence",
                        score=100,
                        confidence=99,
                        status="MALICIOUS",
                        what_was_tested=
                            "Normalized URL and host",
                        finding=explanation,
                        why_it_matters=(
                            "The website has been independently "
                            "identified as phishing by an "
                            "external threat-intelligence source."
                        ),
                        severity="CRITICAL"
                    )
                )

            except Exception:
                pass

            verdict.risk = 100
            verdict.decision = "BLOCK"

            reasons = list(
                getattr(
                    verdict,
                    "reasons",
                    []
                )
            )

            reasons.insert(
                0,
                explanation
            )

            verdict.reasons = reasons

            #
            # Attach metadata for later research use.
            #
            verdict.threat_intel = {
                "matched": True,
                "source": source,
                "match_type": match_type
            }

        else:

            verdict.threat_intel = {
                "matched": False,
                "source": None,
                "match_type": None
            }

        return verdict


#
# Replace engine used by the existing UI.
#
pg.PhishGuardEngine = PhishGuardV24Engine


def main():
    pg.main()


if __name__ == "__main__":
    main()
