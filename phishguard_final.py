import sys
import ssl
import socket
import csv
import os
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

import tldextract

from PySide6.QtCore import Qt, QUrl
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QApplication,
    QMainWindow,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QTextEdit,
    QMessageBox,
    QDialog,
)
from PySide6.QtWebEngineWidgets import QWebEngineView


# ============================================================
# PHISHGUARD FINAL CONSOLIDATED BUILD
# ============================================================

APP_VERSION = "2.4.1-final"

ALLOW_MAX = 44
WARN_MIN = 45
BLOCK_MIN = 70

BASE_DIR = Path(__file__).resolve().parent

THREAT_DIR = BASE_DIR / "threat_intel"
THREAT_DIR.mkdir(exist_ok=True)

PHISHTANK_FILE = THREAT_DIR / "phishtank_verified.csv"
OPENPHISH_FILE = THREAT_DIR / "openphish.txt"

THREAT_CACHE_MAX_AGE = 60 * 60

USER_AGENT = "PhishGuard-DEng-Research/2.4.1"


# ============================================================
# DATA MODELS
# ============================================================

@dataclass
class EvidenceItem:
    category: str
    test_name: str
    score: int
    confidence: int
    status: str
    what_was_tested: str
    finding: str
    why_it_matters: str
    severity: str


@dataclass
class Verdict:
    url: str
    host: str
    unicode_host: str
    domain: str
    risk: int
    decision: str
    reasons: list = field(default_factory=list)
    validations: list = field(default_factory=list)
    tested: list = field(default_factory=list)
    evidence: list = field(default_factory=list)
    tls: dict = field(default_factory=dict)
    brand: dict = field(default_factory=dict)
    threat_intel: dict = field(default_factory=dict)


# ============================================================
# DOMAIN UTILITIES
# ============================================================

TLD_EXTRACT = tldextract.TLDExtract(
    suffix_list_urls=None
)


def ensure_scheme(url):
    url = (url or "").strip()

    if not url:
        return ""

    if "://" not in url:
        url = "https://" + url

    return url


def normalize_host(host):
    return (host or "").strip().lower().rstrip(".")


def idna_to_unicode(host):
    try:
        return host.encode("ascii").decode("idna")
    except Exception:
        return host


def extract_host(url):
    try:
        url = ensure_scheme(url)
        parsed = urllib.parse.urlsplit(url)

        return normalize_host(
            parsed.hostname or ""
        )

    except Exception:
        return ""


def registrable_domain(host):
    host = normalize_host(host)

    if not host:
        return ""

    try:
        ext = TLD_EXTRACT(host)

        if ext.domain and ext.suffix:
            return f"{ext.domain}.{ext.suffix}"

        return host

    except Exception:
        parts = host.split(".")

        if len(parts) >= 2:
            return ".".join(parts[-2:])

        return host


def second_level_label(host):
    domain = registrable_domain(host)

    if "." in domain:
        return domain.split(".")[0]

    return domain


def is_ip_host(host):
    try:
        socket.inet_aton(host)
        return True
    except Exception:
        return False


def normalize_for_typos(text):
    value = (text or "").lower()

    substitutions = {
        "0": "o",
        "1": "l",
        "3": "e",
        "4": "a",
        "5": "s",
        "7": "t",
    }

    for src, dst in substitutions.items():
        value = value.replace(src, dst)

    value = value.replace("rn", "m")
    value = value.replace("vv", "w")
    value = value.replace("cl", "d")

    return value


def levenshtein(a, b):
    a = a or ""
    b = b or ""

    if a == b:
        return 0

    if not a:
        return len(b)

    if not b:
        return len(a)

    previous = list(range(len(b) + 1))

    for i, ca in enumerate(a, start=1):
        current = [i]

        for j, cb in enumerate(b, start=1):
            insert = current[j - 1] + 1
            delete = previous[j] + 1
            replace = previous[j - 1] + (ca != cb)

            current.append(
                min(insert, delete, replace)
            )

        previous = current

    return previous[-1]


def normalize_url(url):
    url = ensure_scheme(url)

    if not url:
        return ""

    try:
        parsed = urllib.parse.urlsplit(url)

        scheme = (
            parsed.scheme or "https"
        ).lower()

        host = normalize_host(
            parsed.hostname or ""
        )

        port = parsed.port

        netloc = host

        if port:
            if not (
                scheme == "https" and port == 443
            ) and not (
                scheme == "http" and port == 80
            ):
                netloc = f"{host}:{port}"

        path = parsed.path or "/"

        while "//" in path:
            path = path.replace("//", "/")

        return urllib.parse.urlunsplit(
            (
                scheme,
                netloc,
                path,
                parsed.query or "",
                "",
            )
        )

    except Exception:
        return url.lower()


# ============================================================
# BRAND AND URL DATA
# ============================================================

KNOWN_BRANDS = {
    "paypal": "paypal.com",
    "microsoft": "microsoft.com",
    "outlook": "microsoft.com",
    "office365": "microsoft.com",
    "google": "google.com",
    "apple": "apple.com",
    "amazon": "amazon.com",
    "bankofamerica": "bankofamerica.com",
    "chase": "chase.com",
    "wellsfargo": "wellsfargo.com",
    "github": "github.com",
    "linkedin": "linkedin.com",
    "facebook": "facebook.com",
    "instagram": "instagram.com",
    "netflix": "netflix.com",
    "docusign": "docusign.com",
    "irs": "irs.gov",
    "ssa": "ssa.gov",
    "usps": "usps.com",
    "fedex": "fedex.com",
    "ups": "ups.com",
    "coinbase": "coinbase.com",
    "binance": "binance.com",
}


PHISHING_TERMS = {
    "login",
    "signin",
    "sign-in",
    "verify",
    "verification",
    "account",
    "password",
    "credential",
    "secure",
    "security",
    "update",
    "confirm",
    "authentication",
    "auth",
    "wallet",
    "payment",
    "invoice",
    "document",
    "shared",
    "recover",
    "unlock",
    "suspended",
    "webmail",
    "office365",
    "microsoft365",
}


SUSPICIOUS_TLDS = {
    "zip",
    "top",
    "click",
    "xyz",
    "work",
    "support",
    "cam",
    "live",
    "rest",
    "fit",
    "buzz",
}


URL_SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "cutt.ly",
    "rebrand.ly",
    "shorturl.at",
}


SHARED_HOSTING = {
    "github.io",
    "pages.dev",
    "workers.dev",
    "vercel.app",
    "netlify.app",
    "web.app",
    "firebaseapp.com",
    "blogspot.com",
    "wixsite.com",
    "weebly.com",
    "duckdns.org",
}


REDIRECT_KEYS = {
    "redirect",
    "redirect_uri",
    "return",
    "returnurl",
    "return_url",
    "continue",
    "next",
    "url",
    "target",
    "destination",
}


SENSITIVE_KEYS = {
    "user",
    "username",
    "email",
    "login",
    "password",
    "pass",
    "token",
    "session",
    "account",
    "auth",
}


# ============================================================
# URL ENGINE
# ============================================================

class URLEngine:

    def analyze(self, url):
        evidence = []

        raw = ensure_scheme(url)

        try:
            parsed = urllib.parse.urlsplit(raw)

        except Exception:
            return evidence

        host = normalize_host(
            parsed.hostname or ""
        )

        decoded = urllib.parse.unquote(
            raw.lower()
        )

        domain = registrable_domain(host)

        if parsed.scheme.lower() != "https":
            evidence.append(
                EvidenceItem(
                    "URL",
                    "HTTPS",
                    8,
                    90,
                    "SUSPICIOUS",
                    "URL scheme",
                    "The website does not use HTTPS.",
                    "Phishing pages may use insecure transport, although HTTPS alone does not establish legitimacy.",
                    "MEDIUM",
                )
            )

        if is_ip_host(host):
            evidence.append(
                EvidenceItem(
                    "URL",
                    "Raw IP address",
                    18,
                    95,
                    "SUSPICIOUS",
                    "Hostname",
                    "The website uses an IP address instead of a normal domain name.",
                    "Credential-harvesting pages sometimes use direct IP addresses to avoid recognizable domains.",
                    "HIGH",
                )
            )

        if "xn--" in host:
            evidence.append(
                EvidenceItem(
                    "URL",
                    "Internationalized domain",
                    10,
                    80,
                    "REVIEW",
                    "Hostname",
                    "The hostname contains Punycode or IDN encoding.",
                    "Internationalized domains are legitimate in many cases but can also be used in visual impersonation attacks.",
                    "MEDIUM",
                )
            )

        if "@" in raw:
            evidence.append(
                EvidenceItem(
                    "URL",
                    "At-sign in URL",
                    15,
                    90,
                    "SUSPICIOUS",
                    "Full URL",
                    "The URL contains an @ character.",
                    "An @ symbol can make the visible portion of a URL misleading.",
                    "HIGH",
                )
            )

        if host.count(".") >= 4:
            evidence.append(
                EvidenceItem(
                    "URL",
                    "Deep subdomain structure",
                    7,
                    70,
                    "SUSPICIOUS",
                    "Hostname",
                    "The hostname contains many subdomain levels.",
                    "Deep subdomains can place trusted-looking words before the actual registered domain.",
                    "MEDIUM",
                )
            )

        hyphens = host.count("-")

        if hyphens >= 3:
            evidence.append(
                EvidenceItem(
                    "URL",
                    "High hyphen density",
                    7,
                    70,
                    "SUSPICIOUS",
                    "Hostname",
                    f"The hostname contains {hyphens} hyphens.",
                    "Excessive separators may be associated with deceptive domains.",
                    "LOW",
                )
            )

        if "." in domain:
            tld = domain.rsplit(".", 1)[-1]

            if tld in SUSPICIOUS_TLDS:
                evidence.append(
                    EvidenceItem(
                        "URL",
                        "Higher-risk TLD",
                        5,
                        55,
                        "REVIEW",
                        "Domain suffix",
                        f"The domain uses .{tld}.",
                        "Some frequently abused TLDs appear in malicious campaigns, although the TLD alone is not proof of phishing.",
                        "LOW",
                    )
                )

        length = len(raw)

        if length >= 180:
            score = 12
        elif length >= 120:
            score = 8
        elif length >= 75:
            score = 4
        else:
            score = 0

        if score:
            evidence.append(
                EvidenceItem(
                    "URL",
                    "Long URL",
                    score,
                    60,
                    "REVIEW",
                    "Full URL length",
                    f"The URL is {length} characters long.",
                    "Very long URLs can conceal meaningful domain or path information.",
                    "LOW",
                )
            )

        if len(host) >= 55:
            evidence.append(
                EvidenceItem(
                    "URL",
                    "Long hostname",
                    7,
                    60,
                    "REVIEW",
                    "Hostname length",
                    f"The hostname is {len(host)} characters long.",
                    "Unusually long hostnames may be associated with generated or deceptive infrastructure.",
                    "LOW",
                )
            )

        path_parts = [
            x
            for x in parsed.path.split("/")
            if x
        ]

        if len(path_parts) >= 8:
            score = 10
        elif len(path_parts) >= 5:
            score = 6
        else:
            score = 0

        if score:
            evidence.append(
                EvidenceItem(
                    "URL",
                    "Deep URL path",
                    score,
                    60,
                    "REVIEW",
                    "URL path",
                    f"The path contains {len(path_parts)} levels.",
                    "Complex path structures can conceal phishing content or generated routing.",
                    "LOW",
                )
            )

        found_terms = sorted(
            {
                term
                for term in PHISHING_TERMS
                if term in decoded
            }
        )

        if len(found_terms) >= 4:
            score = 14
        elif len(found_terms) >= 2:
            score = 10
        elif len(found_terms) == 1:
            score = 5
        else:
            score = 0

        if score:
            evidence.append(
                EvidenceItem(
                    "URL",
                    "Authentication or urgency terminology",
                    score,
                    65,
                    "REVIEW",
                    "URL text",
                    "Detected terms: "
                    + ", ".join(found_terms[:8]),
                    "Authentication, account, payment, or verification terms may support a phishing assessment when combined with other evidence.",
                    "MEDIUM",
                )
            )

        query = urllib.parse.parse_qs(
            parsed.query,
            keep_blank_values=True
        )

        qcount = len(query)

        if qcount >= 9:
            score = 8
        elif qcount >= 5:
            score = 5
        else:
            score = 0

        if score:
            evidence.append(
                EvidenceItem(
                    "URL",
                    "Large number of query parameters",
                    score,
                    55,
                    "REVIEW",
                    "Query string",
                    f"The URL contains {qcount} query parameters.",
                    "Complex query strings can obscure redirection or tracking behavior.",
                    "LOW",
                )
            )

        lower_keys = {
            key.lower()
            for key in query.keys()
        }

        if lower_keys & REDIRECT_KEYS:
            evidence.append(
                EvidenceItem(
                    "URL",
                    "Redirect parameter",
                    5,
                    60,
                    "REVIEW",
                    "Query keys",
                    "Redirect-oriented parameters were detected.",
                    "Redirect parameters can send users to another destination and should be evaluated with other evidence.",
                    "LOW",
                )
            )

        if lower_keys & SENSITIVE_KEYS:
            evidence.append(
                EvidenceItem(
                    "URL",
                    "Authentication-related query fields",
                    7,
                    65,
                    "REVIEW",
                    "Query keys",
                    "Authentication-related query parameters were detected.",
                    "These parameters can appear in legitimate workflows but may also appear in credential-harvesting URLs.",
                    "MEDIUM",
                )
            )

        encoded_count = raw.count("%")

        if encoded_count >= 9:
            score = 9
        elif encoded_count >= 4:
            score = 5
        else:
            score = 0

        if score:
            evidence.append(
                EvidenceItem(
                    "URL",
                    "Heavy URL encoding",
                    score,
                    60,
                    "REVIEW",
                    "Encoded URL characters",
                    f"The URL contains {encoded_count} percent-encoded sequences.",
                    "Heavy encoding can make a URL more difficult for a user to interpret.",
                    "LOW",
                )
            )

        if domain in URL_SHORTENERS:
            evidence.append(
                EvidenceItem(
                    "URL",
                    "URL shortening service",
                    8,
                    65,
                    "REVIEW",
                    "Registered domain",
                    "The website uses a URL-shortening service.",
                    "Shortened links hide the eventual destination from the user.",
                    "MEDIUM",
                )
            )

        if domain in SHARED_HOSTING:
            evidence.append(
                EvidenceItem(
                    "URL",
                    "Shared hosting platform",
                    5,
                    45,
                    "REVIEW",
                    "Registered domain",
                    "The site is hosted on a commonly shared hosting platform.",
                    "Shared hosting is legitimate, but phishing pages are also frequently deployed on easy-to-create hosted subdomains.",
                    "LOW",
                )
            )

        digits = sum(
            character.isdigit()
            for character in host
        )

        if (
            len(host) > 0
            and digits / len(host) >= 0.30
        ):
            evidence.append(
                EvidenceItem(
                    "URL",
                    "High numeric hostname content",
                    6,
                    60,
                    "REVIEW",
                    "Hostname",
                    "A large portion of the hostname consists of digits.",
                    "Generated or disposable infrastructure may use highly numeric hostnames.",
                    "LOW",
                )
            )

        return evidence


# ============================================================
# BRAND ENGINE
# ============================================================

class BrandEngine:

    def analyze(self, url):
        host = extract_host(url)

        domain = registrable_domain(host)
        label = second_level_label(host)

        compact_host = (
            normalize_for_typos(host)
            .replace("-", "")
            .replace(".", "")
        )

        result = {
            "official": False,
            "score": 0,
            "brand": None,
            "official_domain": None,
            "finding": None,
        }

        evidence = []

        for brand, official_domain in KNOWN_BRANDS.items():

            if (
                domain == official_domain
                or host.endswith("." + official_domain)
            ):
                result.update(
                    {
                        "official": True,
                        "score": 0,
                        "brand": brand,
                        "official_domain": official_domain,
                        "finding": "Official domain match",
                    }
                )

                return result, evidence

        best = None

        for brand, official_domain in KNOWN_BRANDS.items():

            brand_norm = (
                normalize_for_typos(brand)
                .replace("-", "")
            )

            label_norm = (
                normalize_for_typos(label)
                .replace("-", "")
            )

            distance = levenshtein(
                label_norm,
                brand_norm
            )

            if best is None or distance < best[0]:
                best = (
                    distance,
                    brand,
                    official_domain
                )

            if (
                brand_norm in compact_host
                and official_domain != domain
            ):
                result.update(
                    {
                        "score": max(
                            result["score"],
                            70
                        ),
                        "brand": brand,
                        "official_domain": official_domain,
                        "finding": "Brand name appears outside the official domain",
                    }
                )

        if best:
            distance, brand, official = best

            brand_len = max(
                len(brand),
                1
            )

            ratio = distance / brand_len

            if distance == 1:
                score = 80
            elif distance == 2 and ratio <= 0.35:
                score = 65
            elif distance == 3 and ratio <= 0.35:
                score = 50
            else:
                score = 0

            if score > result["score"]:
                result.update(
                    {
                        "score": score,
                        "brand": brand,
                        "official_domain": official,
                        "finding": f"Domain resembles {brand}",
                    }
                )

        if result["score"] >= 50:
            evidence.append(
                EvidenceItem(
                    "Brand",
                    "Brand impersonation / typosquatting",
                    28 if result["score"] >= 65 else 16,
                    85,
                    "SUSPICIOUS",
                    "Domain similarity to known brands",
                    result["finding"]
                    or "Possible brand impersonation detected.",
                    (
                        f"The domain resembles or references "
                        f"{result['brand']} but is not the "
                        f"official domain "
                        f"{result['official_domain']}."
                    ),
                    "HIGH",
                )
            )

        return result, evidence


# ============================================================
# TLS ENGINE
# ============================================================

class TLSEngine:

    def analyze(self, host):
        result = {
            "validated": False,
            "subject": None,
            "issuer": None,
            "days_left": None,
            "error": None,
            "score": 0,
        }

        if not host:
            result["error"] = "No hostname available."
            result["score"] = 8
            return result

        try:
            context = ssl.create_default_context()

            with socket.create_connection(
                (host, 443),
                timeout=4,
            ) as sock:

                with context.wrap_socket(
                    sock,
                    server_hostname=host,
                ) as tls_sock:

                    cert = tls_sock.getpeercert()

            result["validated"] = True

            subject = dict(
                item[0]
                for item in cert.get(
                    "subject",
                    []
                )
            )

            issuer = dict(
                item[0]
                for item in cert.get(
                    "issuer",
                    []
                )
            )

            result["subject"] = subject.get(
                "commonName",
                "Unknown"
            )

            result["issuer"] = issuer.get(
                "commonName",
                "Unknown"
            )

            not_after = cert.get("notAfter")

            if not_after:
                expiry = datetime.strptime(
                    not_after,
                    "%b %d %H:%M:%S %Y %Z",
                )

                delta = (
                    expiry
                    - datetime.utcnow()
                )

                result["days_left"] = delta.days

                if delta.days < 0:
                    result["score"] = 30
                elif delta.days <= 7:
                    result["score"] = 8

        except ssl.SSLCertVerificationError as exc:
            result["error"] = (
                "Certificate validation failed: "
                + str(exc)
            )
            result["score"] = 20

        except socket.timeout:
            result["error"] = (
                "TLS connection timed out."
            )
            result["score"] = 5

        except socket.gaierror:
            result["error"] = (
                "Hostname could not be resolved."
            )
            result["score"] = 8

        except Exception as exc:
            result["error"] = str(exc)
            result["score"] = 5

        return result


# ============================================================
# THREAT INTELLIGENCE
# ============================================================

def cache_is_fresh(path):
    if not path.exists():
        return False

    age = (
        time.time()
        - path.stat().st_mtime
    )

    return age < THREAT_CACHE_MAX_AGE


def download_file(url, destination):
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": USER_AGENT
        }
    )

    with urllib.request.urlopen(
        request,
        timeout=30,
    ) as response:

        data = response.read()

    temp = Path(
        str(destination) + ".tmp"
    )

    temp.write_bytes(data)
    temp.replace(destination)


def update_phishtank():
    if cache_is_fresh(
        PHISHTANK_FILE
    ):
        return

    app_key = os.environ.get(
        "PHISHTANK_APP_KEY",
        "",
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
            "Updating PhishTank cache..."
        )

        download_file(
            url,
            PHISHTANK_FILE,
        )

        print(
            "PhishTank cache updated."
        )

    except Exception as exc:
        print(
            "PhishTank update unavailable:",
            exc,
        )


def update_openphish():
    if cache_is_fresh(
        OPENPHISH_FILE
    ):
        return

    feed = (
        "https://raw.githubusercontent.com/"
        "openphish/public_feed/"
        "refs/heads/main/feed.txt"
    )

    try:
        print(
            "Updating OpenPhish cache..."
        )

        download_file(
            feed,
            OPENPHISH_FILE,
        )

        print(
            "OpenPhish cache updated."
        )

    except Exception as exc:
        print(
            "OpenPhish update unavailable:",
            exc,
        )


class ThreatIntelEngine:

    def __init__(self):
        self.urls = set()
        self.hosts = set()
        self.sources = {}

        update_phishtank()
        update_openphish()

        self.load()

    def add(self, url, source):
        normalized = normalize_url(url)

        if not normalized:
            return

        host = extract_host(normalized)

        self.urls.add(normalized)

        self.sources[normalized] = source

        if host:
            self.hosts.add(host)

    def load(self):

        if PHISHTANK_FILE.exists():

            try:
                with PHISHTANK_FILE.open(
                    "r",
                    newline="",
                    encoding="utf-8-sig",
                    errors="replace",
                ) as file:

                    reader = csv.DictReader(file)

                    for row in reader:

                        url = (
                            row.get(
                                "url",
                                "",
                            )
                            .strip()
                        )

                        verified = (
                            row.get(
                                "verified",
                                "",
                            )
                            .strip()
                            .lower()
                        )

                        online = (
                            row.get(
                                "online",
                                "",
                            )
                            .strip()
                            .lower()
                        )

                        if (
                            url
                            and verified == "yes"
                            and online == "yes"
                        ):
                            self.add(
                                url,
                                "PhishTank",
                            )

            except Exception as exc:
                print(
                    "Unable to read PhishTank cache:",
                    exc,
                )

        if OPENPHISH_FILE.exists():

            try:
                with OPENPHISH_FILE.open(
                    "r",
                    encoding="utf-8",
                    errors="replace",
                ) as file:

                    for line in file:
                        url = line.strip()

                        if (
                            url
                            and not url.startswith("#")
                        ):
                            self.add(
                                url,
                                "OpenPhish",
                            )

            except Exception as exc:
                print(
                    "Unable to read OpenPhish cache:",
                    exc,
                )

        print(
            f"Known phishing URLs: "
            f"{len(self.urls):,}"
        )

        print(
            f"Known phishing hosts: "
            f"{len(self.hosts):,}"
        )

    def check(self, url):
        normalized = normalize_url(url)

        host = extract_host(url)

        if normalized in self.urls:
            return {
                "matched": True,
                "match_type": "EXACT_URL",
                "source": self.sources.get(
                    normalized,
                    "Threat intelligence",
                ),
            }

        try:
            parsed = urllib.parse.urlsplit(
                normalized
            )

            alternate_scheme = (
                "http"
                if parsed.scheme == "https"
                else "https"
            )

            alternate = (
                urllib.parse.urlunsplit(
                    (
                        alternate_scheme,
                        parsed.netloc,
                        parsed.path,
                        parsed.query,
                        "",
                    )
                )
            )

            if alternate in self.urls:
                return {
                    "matched": True,
                    "match_type": "NORMALIZED_URL",
                    "source": self.sources.get(
                        alternate,
                        "Threat intelligence",
                    ),
                }

        except Exception:
            pass

        if host and host in self.hosts:
    return {
        "matched": False,
        "match_type": None,
        "source": None,
    }

        return {
            "matched": False,
            "match_type": None,
            "source": None,
        }


# ============================================================
# MAIN PHISHGUARD ENGINE
# ============================================================

class PhishGuardEngine:

    def __init__(self):
        self.url_engine = URLEngine()
        self.brand_engine = BrandEngine()
        self.tls_engine = TLSEngine()
        self.threat_engine = ThreatIntelEngine()

    def local_risk(
        self,
        evidence,
        brand,
        tls,
    ):
        risk = sum(
            item.score
            for item in evidence
        )

        if brand.get(
            "official"
        ):
            risk -= 25

        return max(
            0,
            min(
                99,
                risk,
            ),
        )

    def analyze(self, url):
        url = ensure_scheme(url)

        host = extract_host(url)

        unicode_host = idna_to_unicode(
            host
        )

        domain = registrable_domain(
            host
        )

        evidence = []

        evidence.extend(
            self.url_engine.analyze(
                url
            )
        )

        brand, brand_evidence = (
            self.brand_engine.analyze(
                url
            )
        )

        evidence.extend(
            brand_evidence
        )

        tls = self.tls_engine.analyze(
            host
        )

        if tls.get(
            "score",
            0
        ) > 0:
            evidence.append(
                EvidenceItem(
                    "TLS",
                    "TLS certificate assessment",
                    tls.get(
                        "score",
                        0
                    ),
                    80,
                    "SUSPICIOUS",
                    "TLS certificate",
                    tls.get(
                        "error"
                    )
                    or "TLS certificate concern detected.",
                    "TLS problems may indicate misconfiguration or malicious infrastructure, but TLS is evaluated together with other evidence.",
                    "MEDIUM",
                )
            )

        local_risk = self.local_risk(
            evidence,
            brand,
            tls,
        )

        intel = self.threat_engine.check(
            url
        )

        risk = local_risk
        reasons = []

        if (
            intel["matched"]
            and intel["match_type"]
            == "EXACT_URL"
        ):
            risk = 100
            decision = "BLOCK"

            reason = (
                "This exact website address appears "
                "in independently verified phishing intelligence."
            )

            evidence.append(
                EvidenceItem(
                    "Threat Intelligence",
                    "Exact verified phishing URL",
                    100,
                    99,
                    "MALICIOUS",
                    "Normalized URL",
                    reason,
                    "An exact verified phishing URL match provides the strongest reputation evidence.",
                    "CRITICAL",
                )
            )

            reasons.append(reason)

        elif (
            intel["matched"]
            and intel["match_type"]
            == "NORMALIZED_URL"
        ):
            risk = max(
                95,
                local_risk
            )

            risk = min(
                risk,
                99
            )

            decision = "BLOCK"

            reason = (
                "A normalized form of this website "
                "matches independently verified phishing intelligence."
            )

            evidence.append(
                EvidenceItem(
                    "Threat Intelligence",
                    "Normalized phishing URL match",
                    95,
                    97,
                    "MALICIOUS",
                    "Normalized URL",
                    reason,
                    "The submitted URL resolves to the same normalized address as a verified phishing record.",
                    "CRITICAL",
                )
            )

            reasons.append(reason)

        elif (
            intel["matched"]
            and intel["match_type"]
            == "HOST"
        ):
            risk = max(
                85,
                local_risk
            )

            risk = min(
                risk,
                99
            )

            decision = "BLOCK"

            reason = (
                "This website uses a host associated "
                "with independently reported phishing activity."
            )

            evidence.append(
                EvidenceItem(
                    "Threat Intelligence",
                    "Phishing-associated host",
                    85,
                    92,
                    "MALICIOUS",
                    "Hostname",
                    reason,
                    "The exact page may differ from the reported phishing page, but the same host appears in phishing intelligence.",
                    "HIGH",
                )
            )

            reasons.append(reason)

        else:
            if risk >= BLOCK_MIN:
                decision = "BLOCK"

                reasons.append(
                    "PhishGuard detected a strong combination of suspicious characteristics."
                )

            elif risk >= WARN_MIN:
                decision = "WARN"

                reasons.append(
                    "PhishGuard detected multiple suspicious characteristics. Independent verification is recommended."
                )

            else:
                decision = "ALLOW"

                reasons.append(
                    "The current analysis did not accumulate enough evidence to warn or block this website."
                )

        return Verdict(
            url=url,
            host=host,
            unicode_host=unicode_host,
            domain=domain,
            risk=risk,
            decision=decision,
            reasons=reasons,
            evidence=evidence,
            tls=tls,
            brand=brand,
            threat_intel={
                **intel,
                "local_risk": local_risk,
                "final_risk": risk,
            },
        )


# ============================================================
# RESULT DIALOG
# ============================================================

class ThreatDialog(QDialog):

    def __init__(
        self,
        verdict,
        parent=None,
    ):
        super().__init__(parent)

        self.verdict = verdict

        self.setWindowTitle(
            "PhishGuard Security Analysis"
        )

        self.resize(
            760,
            650,
        )

        layout = QVBoxLayout(
            self
        )

        title = QLabel()

        if verdict.decision == "ALLOW":
            title.setText(
                "ALLOW — No Strong Threat Detected"
            )

            title.setStyleSheet(
                """
                QLabel {
                    background-color: #14532d;
                    color: white;
                    font-size: 22px;
                    font-weight: bold;
                    padding: 18px;
                    border-radius: 6px;
                }
                """
            )

        elif verdict.decision == "WARN":
            title.setText(
                "WARN — Suspicious Website"
            )

            title.setStyleSheet(
                """
                QLabel {
                    background-color: #92400e;
                    color: white;
                    font-size: 22px;
                    font-weight: bold;
                    padding: 18px;
                    border-radius: 6px;
                }
                """
            )

        else:
            title.setText(
                "BLOCK — Potential Phishing Website"
            )

            title.setStyleSheet(
                """
                QLabel {
                    background-color: #991b1b;
                    color: white;
                    font-size: 22px;
                    font-weight: bold;
                    padding: 18px;
                    border-radius: 6px;
                }
                """
            )

        layout.addWidget(title)

        risk = QLabel(
            f"Risk Score: "
            f"{verdict.risk}/100"
        )

        risk.setStyleSheet(
            """
            QLabel {
                font-size: 20px;
                font-weight: bold;
                padding: 8px;
            }
            """
        )

        layout.addWidget(risk)

        site = QLabel(
            f"Website: "
            f"{verdict.url}\n\n"
            f"Domain: "
            f"{verdict.domain}"
        )

        site.setWordWrap(True)

        site.setStyleSheet(
            "font-size: 14px;"
        )

        layout.addWidget(site)

        details = QTextEdit()
        details.setReadOnly(True)

        lines = []

        lines.append(
            "PHISHGUARD DECISION"
        )

        lines.append(
            "=" * 50
        )

        for reason in verdict.reasons:
            lines.append(
                f"• {reason}"
            )

        lines.append("")
        lines.append(
            "THREAT INTELLIGENCE"
        )
        lines.append(
            "=" * 50
        )

        intel = verdict.threat_intel

        if intel.get("matched"):
            lines.append(
                "Match found: YES"
            )

            lines.append(
                f"Match type: "
                f"{intel.get('match_type')}"
            )

            lines.append(
                f"Source: "
                f"{intel.get('source')}"
            )

        else:
            lines.append(
                "Known-phishing match: NO"
            )

        lines.append(
            f"Local heuristic risk: "
            f"{intel.get('local_risk', 0)}/100"
        )

        lines.append("")
        lines.append(
            "TECHNICAL EVIDENCE"
        )
        lines.append(
            "=" * 50
        )

        if not verdict.evidence:
            lines.append(
                "No significant suspicious indicators were recorded."
            )

        for item in verdict.evidence:
            lines.append("")
            lines.append(
                item.test_name
            )

            lines.append(
                f"Category: "
                f"{item.category}"
            )

            lines.append(
                f"Severity: "
                f"{item.severity}"
            )

            lines.append(
                f"Score contribution: "
                f"{item.score}"
            )

            lines.append(
                f"Finding: "
                f"{item.finding}"
            )

            lines.append(
                f"Why it matters: "
                f"{item.why_it_matters}"
            )

        lines.append("")
        lines.append(
            "TLS ASSESSMENT"
        )
        lines.append(
            "=" * 50
        )

        tls = verdict.tls

        lines.append(
            f"Certificate validated: "
            f"{tls.get('validated')}"
        )

        if tls.get("issuer"):
            lines.append(
                f"Issuer: "
                f"{tls.get('issuer')}"
            )

        if tls.get("days_left") is not None:
            lines.append(
                f"Days until expiration: "
                f"{tls.get('days_left')}"
            )

        if tls.get("error"):
            lines.append(
                f"TLS finding: "
                f"{tls.get('error')}"
            )

        lines.append("")
        lines.append(
            "IMPORTANT"
        )
        lines.append(
            "=" * 50
        )

        if verdict.decision == "ALLOW":
            lines.append(
                "ALLOW does not guarantee that a website is safe. It means that the current PhishGuard analysis did not accumulate enough evidence to warn or block the site."
            )

        elif verdict.decision == "WARN":
            lines.append(
                "PhishGuard recommends independently verifying the website before continuing or entering sensitive information."
            )

        else:
            lines.append(
                "PhishGuard recommends that the user not continue to this website."
            )

        details.setPlainText(
            "\n".join(lines)
        )

        details.setStyleSheet(
            """
            QTextEdit {
                font-size: 14px;
                padding: 10px;
            }
            """
        )

        layout.addWidget(details)

        close_button = QPushButton(
            "Close"
        )

        close_button.setMinimumHeight(
            42
        )

        close_button.clicked.connect(
            self.accept
        )

        layout.addWidget(
            close_button
        )


# ============================================================
# MAIN BROWSER
# ============================================================

class Browser(QMainWindow):

    def __init__(self):
        super().__init__()

        self.engine = PhishGuardEngine()

        self.setWindowTitle(
            f"PhishGuard {APP_VERSION}"
        )

        self.resize(
            1200,
            820,
        )

        root = QWidget()

        self.setCentralWidget(
            root
        )

        main_layout = QVBoxLayout(
            root
        )

        header = QLabel(
            "PhishGuard"
        )

        header.setAlignment(
            Qt.AlignCenter
        )

        header.setStyleSheet(
            """
            QLabel {
                font-size: 30px;
                font-weight: bold;
                padding: 14px;
            }
            """
        )

        main_layout.addWidget(
            header
        )

        subtitle = QLabel(
            "Explainable Phishing Website Detection"
        )

        subtitle.setAlignment(
            Qt.AlignCenter
        )

        subtitle.setStyleSheet(
            """
            QLabel {
                font-size: 16px;
                padding-bottom: 8px;
            }
            """
        )

        main_layout.addWidget(
            subtitle
        )

        controls = QHBoxLayout()

        self.address = QLineEdit()

        self.address.setPlaceholderText(
            "Enter a website or URL..."
        )

        self.address.setMinimumHeight(
            42
        )

        self.address.setStyleSheet(
            "font-size: 16px;"
        )

        controls.addWidget(
            self.address
        )

        self.analyze_button = QPushButton(
            "Analyze Only"
        )

        self.analyze_button.setMinimumHeight(
            42
        )

        self.analyze_button.clicked.connect(
            self.analyze_only
        )

        controls.addWidget(
            self.analyze_button
        )

        self.go_button = QPushButton(
            "Go"
        )

        self.go_button.setMinimumHeight(
            42
        )

        self.go_button.clicked.connect(
            self.go
        )

        controls.addWidget(
            self.go_button
        )

        main_layout.addLayout(
            controls
        )

        self.status = QLabel(
            "Ready"
        )

        self.status.setStyleSheet(
            """
            QLabel {
                font-size: 14px;
                font-weight: bold;
                padding: 8px;
            }
            """
        )

        main_layout.addWidget(
            self.status
        )

        self.web = QWebEngineView()

        main_layout.addWidget(
            self.web
        )

        self.address.returnPressed.connect(
            self.analyze_only
        )

    def run_analysis(
        self,
        load_if_safe=False,
    ):

        url = self.address.text().strip()

        if not url:
            QMessageBox.warning(
                self,
                "PhishGuard",
                "Please enter a website address.",
            )
            return

        url = ensure_scheme(
            url
        )

        self.address.setText(
            url
        )

        self.status.setText(
            "Analyzing website..."
        )

        QApplication.processEvents()

        try:
            verdict = self.engine.analyze(
                url
            )

        except Exception as exc:
            QMessageBox.critical(
                self,
                "Analysis Error",
                str(exc),
            )

            self.status.setText(
                "Analysis failed."
            )

            return

        self.status.setText(
            f"{verdict.decision} | "
            f"Risk "
            f"{verdict.risk}/100"
        )

        dialog = ThreatDialog(
            verdict,
            self,
        )

        dialog.exec()

        if (
            load_if_safe
            and verdict.decision
            == "ALLOW"
        ):
            self.web.setUrl(
                QUrl(url)
            )

        elif load_if_safe:
            self.show_block_page(
                verdict
            )

    def analyze_only(self):
        self.run_analysis(
            load_if_safe=False
        )

    def go(self):
        self.run_analysis(
            load_if_safe=True
        )

    def show_block_page(
        self,
        verdict,
    ):

        html = f"""
        <html>
        <body style="
            font-family: Arial;
            margin: 60px;
            background: #f5f5f5;
        ">
            <div style="
                max-width: 800px;
                margin: auto;
                background: white;
                padding: 40px;
                border-radius: 12px;
                border: 3px solid #991b1b;
            ">
                <h1 style="
                    color: #991b1b;
                ">
                    PhishGuard blocked navigation
                </h1>

                <h2>
                    Decision:
                    {verdict.decision}
                </h2>

                <h2>
                    Risk:
                    {verdict.risk}/100
                </h2>

                <p style="
                    font-size: 18px;
                ">
                    PhishGuard did not load this website because
                    the analysis produced a warning or block
                    decision.
                </p>

                <p style="
                    font-size: 18px;
                ">
                    Use the technical analysis dialog to review
                    the reasons for the decision.
                </p>
            </div>
        </body>
        </html>
        """

        self.web.setHtml(
            html
        )


# ============================================================
# APPLICATION ENTRY POINT
# ============================================================

def main():

    print()
    print(
        "=" * 64
    )

    print(
        "PHISHGUARD FINAL BUILD"
    )

    print(
        "=" * 64
    )

    print(
        "0-44   : ALLOW"
    )

    print(
        "45-69  : WARN"
    )

    print(
        "70-99  : BLOCK"
    )

    print(
        "100    : Exact verified phishing URL"
    )

    print(
        "=" * 64
    )

    app = QApplication(
        sys.argv
    )

    app.setApplicationName(
        "PhishGuard"
    )

    app.setFont(
        QFont(
            "Arial",
            11,
        )
    )

    window = Browser()

    window.show()

    sys.exit(
        app.exec()
    )


if __name__ == "__main__":
    main()
