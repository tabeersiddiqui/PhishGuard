#!/usr/bin/env python3
"""
PhishGuard v2.3 Research Build

Purpose:
- Preserve the existing PhishGuard v2.2 GUI and workflow.
- Add stronger local phishing URL/domain/path/query indicators.
- Correct research risk aggregation without changing the original v2.2 file.
- Preserve TLS behavior during normal/manual GUI use.

IMPORTANT:
This file imports phishguard_v22.py. The original v2.2 file is not modified.
"""

import math
import re
import urllib.parse
from collections import Counter

import tldextract
import phishguard_v22 as pg


# Save original class before monkey-patching.
BasePhishGuardEngine = pg.PhishGuardEngine


# ============================================================
# RESEARCH CONFIGURATION
# ============================================================

ALLOW_MAX = 44
WARN_MIN = 45
BLOCK_MIN = 70


# Use tldextract's bundled PSL snapshot instead of downloading
# anything at runtime.
_extract = tldextract.TLDExtract(suffix_list_urls=None)


PHISHING_TERMS = {
    "login",
    "log-in",
    "signin",
    "sign-in",
    "verify",
    "verification",
    "account",
    "password",
    "passwd",
    "credential",
    "credentials",
    "secure",
    "security",
    "update",
    "confirm",
    "confirmation",
    "authenticate",
    "authentication",
    "auth",
    "wallet",
    "payment",
    "invoice",
    "document",
    "shared",
    "recover",
    "recovery",
    "unlock",
    "suspended",
    "suspension",
    "webmail",
    "office365",
    "microsoft365"
}


REDIRECT_KEYS = {
    "redirect",
    "redirect_uri",
    "redirect_url",
    "return",
    "returnurl",
    "return_url",
    "continue",
    "next",
    "url",
    "target",
    "destination",
    "dest"
}


SENSITIVE_QUERY_KEYS = {
    "token",
    "session",
    "sessionid",
    "auth",
    "authentication",
    "password",
    "passwd",
    "email",
    "username",
    "user",
    "account",
    "verify"
}


SHORTENER_DOMAINS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "cutt.ly",
    "rebrand.ly",
    "shorturl.at"
}


SHARED_HOSTING_DOMAINS = {
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
    "duckdns.org"
}


BRAND_REFERENCE = {
    "paypal": "paypal.com",
    "microsoft": "microsoft.com",
    "office365": "microsoft.com",
    "outlook": "microsoft.com",
    "google": "google.com",
    "gmail": "google.com",
    "apple": "apple.com",
    "icloud": "apple.com",
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
    "binance": "binance.com"
}


def add_evidence(
    evidence,
    category,
    test_name,
    score,
    confidence,
    status,
    what_was_tested,
    finding,
    why_it_matters,
    severity
):
    evidence.append(
        pg.EvidenceItem(
            category=category,
            test_name=test_name,
            score=score,
            confidence=confidence,
            status=status,
            what_was_tested=what_was_tested,
            finding=finding,
            why_it_matters=why_it_matters,
            severity=severity
        )
    )


def registered_domain(host):
    ext = _extract(host)

    if ext.domain and ext.suffix:
        return f"{ext.domain}.{ext.suffix}".lower()

    return host.lower()


def entropy(text):
    if not text:
        return 0.0

    counts = Counter(text)
    length = len(text)

    return -sum(
        (count / length) * math.log2(count / length)
        for count in counts.values()
    )


def host_matches_domain(host, domain):
    host = host.lower().strip(".")
    domain = domain.lower().strip(".")

    return host == domain or host.endswith("." + domain)


def enhanced_local_evidence(url):
    evidence = []

    try:
        parsed = urllib.parse.urlsplit(url)
    except Exception:
        return evidence

    scheme = (parsed.scheme or "").lower()
    host = (parsed.hostname or "").lower()
    path = urllib.parse.unquote(parsed.path or "")
    query = parsed.query or ""
    fragment = parsed.fragment or ""

    full_lower = urllib.parse.unquote(url).lower()
    path_query_lower = (path + "?" + query + "#" + fragment).lower()

    reg_domain = registered_domain(host) if host else ""

    # --------------------------------------------------------
    # 1. Nonstandard scheme
    # --------------------------------------------------------

    if scheme and scheme not in {"http", "https"}:
        add_evidence(
            evidence,
            "URL Structure",
            "Nonstandard URL scheme",
            15,
            95,
            "SUSPICIOUS",
            "URL scheme",
            f"The URL uses the {scheme} scheme instead of HTTP or HTTPS.",
            "Unexpected URL schemes may be used to invoke behavior outside ordinary website navigation.",
            "HIGH"
        )

    # --------------------------------------------------------
    # 2. Overall URL length
    # --------------------------------------------------------

    url_length = len(url)

    if url_length >= 180:
        score = 12
        severity = "HIGH"
    elif url_length >= 120:
        score = 8
        severity = "MEDIUM"
    elif url_length >= 75:
        score = 4
        severity = "LOW"
    else:
        score = 0
        severity = "INFO"

    if score:
        add_evidence(
            evidence,
            "URL Structure",
            "Long URL",
            score,
            75,
            "SUSPICIOUS",
            "Total URL length",
            f"The URL contains {url_length} characters.",
            "Unusually long URLs can conceal destination details or embed deceptive parameters.",
            severity
        )

    # --------------------------------------------------------
    # 3. Hostname length
    # --------------------------------------------------------

    if len(host) >= 55:
        add_evidence(
            evidence,
            "Domain Structure",
            "Long hostname",
            7,
            75,
            "SUSPICIOUS",
            "Hostname length",
            f"The hostname contains {len(host)} characters.",
            "Long hostnames can make the actual registrable domain harder for a user to recognize.",
            "MEDIUM"
        )

    # --------------------------------------------------------
    # 4. Path depth
    # --------------------------------------------------------

    path_segments = [
        x for x in path.split("/")
        if x
    ]

    if len(path_segments) >= 8:
        score = 10
        severity = "HIGH"
    elif len(path_segments) >= 5:
        score = 6
        severity = "MEDIUM"
    else:
        score = 0
        severity = "INFO"

    if score:
        add_evidence(
            evidence,
            "URL Structure",
            "Deep URL path",
            score,
            75,
            "SUSPICIOUS",
            "URL path structure",
            f"The URL contains {len(path_segments)} non-empty path levels.",
            "Deep paths can obscure the actual location of content and are useful as a supporting phishing indicator.",
            severity
        )

    # --------------------------------------------------------
    # 5. Full-path phishing terminology
    # --------------------------------------------------------

    found_terms = sorted({
        term
        for term in PHISHING_TERMS
        if term in path_query_lower
    })

    if len(found_terms) >= 4:
        term_score = 14
        severity = "HIGH"
    elif len(found_terms) >= 2:
        term_score = 10
        severity = "MEDIUM"
    elif len(found_terms) == 1:
        term_score = 5
        severity = "LOW"
    else:
        term_score = 0
        severity = "INFO"

    if term_score:
        add_evidence(
            evidence,
            "Lexical Analysis",
            "Authentication or urgency terminology",
            term_score,
            80,
            "SUSPICIOUS",
            "Decoded path, query, and fragment",
            "The URL contains phishing-associated terms: "
            + ", ".join(found_terms[:8]),
            "Authentication, verification, recovery, payment, and urgency terms are commonly used in credential-harvesting and deceptive website URLs.",
            severity
        )

    # --------------------------------------------------------
    # 6. Query parameter count
    # --------------------------------------------------------

    query_pairs = urllib.parse.parse_qsl(
        query,
        keep_blank_values=True
    )

    query_count = len(query_pairs)

    if query_count >= 9:
        score = 8
        severity = "HIGH"
    elif query_count >= 5:
        score = 5
        severity = "MEDIUM"
    else:
        score = 0
        severity = "INFO"

    if score:
        add_evidence(
            evidence,
            "URL Structure",
            "Large query parameter set",
            score,
            70,
            "SUSPICIOUS",
            "Query-string parameter count",
            f"The URL contains {query_count} query parameters.",
            "Large query strings may be used to conceal redirects, tracking values, or authentication-related information.",
            severity
        )

    # --------------------------------------------------------
    # 7. Redirect-oriented query keys
    # --------------------------------------------------------

    query_keys = {
        key.lower()
        for key, value in query_pairs
    }

    redirect_hits = sorted(
        query_keys.intersection(REDIRECT_KEYS)
    )

    if redirect_hits:
        add_evidence(
            evidence,
            "URL Structure",
            "Redirect parameter",
            5,
            70,
            "SUSPICIOUS",
            "Query parameter names",
            "Redirect-related parameter(s) detected: "
            + ", ".join(redirect_hits),
            "Redirect parameters can move users from an apparently familiar URL to a different destination.",
            "LOW"
        )

    # --------------------------------------------------------
    # 8. Sensitive/authentication query keys
    # --------------------------------------------------------

    sensitive_hits = sorted(
        query_keys.intersection(SENSITIVE_QUERY_KEYS)
    )

    if sensitive_hits:
        add_evidence(
            evidence,
            "Lexical Analysis",
            "Authentication-related query parameter",
            7,
            80,
            "SUSPICIOUS",
            "Query parameter names",
            "Authentication-related parameter(s) detected: "
            + ", ".join(sensitive_hits),
            "Authentication-related URL parameters can be relevant when evaluating credential-harvesting behavior.",
            "MEDIUM"
        )

    # --------------------------------------------------------
    # 9. Percent encoding density
    # --------------------------------------------------------

    encoded_count = len(
        re.findall(r"%[0-9a-fA-F]{2}", url)
    )

    if encoded_count >= 9:
        score = 9
        severity = "HIGH"
    elif encoded_count >= 4:
        score = 5
        severity = "MEDIUM"
    else:
        score = 0
        severity = "INFO"

    if score:
        add_evidence(
            evidence,
            "URL Structure",
            "Encoded URL content",
            score,
            80,
            "SUSPICIOUS",
            "Percent-encoded sequences",
            f"The URL contains {encoded_count} percent-encoded sequences.",
            "Heavy encoding may make a URL more difficult for a user to visually interpret.",
            severity
        )

    # --------------------------------------------------------
    # 10. Repeated special-character structure
    # --------------------------------------------------------

    special_count = sum(
        full_lower.count(character)
        for character in ["-", "_", ".", "=", "&"]
    )

    if special_count >= 25:
        add_evidence(
            evidence,
            "URL Structure",
            "High structural complexity",
            6,
            70,
            "SUSPICIOUS",
            "Special-character density",
            f"The URL contains {special_count} structural delimiter characters.",
            "Highly complex URL structures can reduce readability and make deceptive destinations harder to inspect.",
            "MEDIUM"
        )

    # --------------------------------------------------------
    # 11. Entropy of long URL components
    # --------------------------------------------------------

    entropy_target = (
        (parsed.path or "")
        + (parsed.query or "")
    )

    ent = entropy(entropy_target)

    if len(entropy_target) >= 30 and ent >= 4.45:
        add_evidence(
            evidence,
            "Lexical Analysis",
            "High character entropy",
            6,
            65,
            "SUSPICIOUS",
            "Path and query character distribution",
            f"The path/query entropy is {ent:.2f} bits per character.",
            "High-entropy URL components can indicate generated, obfuscated, or difficult-to-read URL content.",
            "MEDIUM"
        )

    # --------------------------------------------------------
    # 12. Known URL shortener
    # --------------------------------------------------------

    if reg_domain in SHORTENER_DOMAINS:
        add_evidence(
            evidence,
            "Domain Structure",
            "URL shortening service",
            8,
            85,
            "SUSPICIOUS",
            "Registrable domain",
            f"The URL uses the shortening service {reg_domain}.",
            "Shortened URLs hide the final destination from the user before navigation.",
            "MEDIUM"
        )

    # --------------------------------------------------------
    # 13. Shared/free-hosting platform
    # --------------------------------------------------------

    if any(
        host_matches_domain(host, service)
        for service in SHARED_HOSTING_DOMAINS
    ):
        add_evidence(
            evidence,
            "Domain Structure",
            "Shared hosting platform",
            5,
            60,
            "CONTEXT",
            "Registrable/hosting domain",
            f"The site is hosted under {reg_domain}.",
            "Shared hosting platforms are legitimate services but can also be abused for temporary deceptive pages; this signal is intentionally low-weight.",
            "LOW"
        )

    # --------------------------------------------------------
    # 14. Brand name outside official brand domain
    # --------------------------------------------------------

    compact_text = re.sub(
        r"[^a-z0-9]",
        "",
        full_lower
    )

    brand_hits = []

    for brand, official_domain in BRAND_REFERENCE.items():

        compact_brand = re.sub(
            r"[^a-z0-9]",
            "",
            brand.lower()
        )

        if (
            compact_brand in compact_text
            and not host_matches_domain(host, official_domain)
        ):
            brand_hits.append(
                (brand, official_domain)
            )

    if brand_hits:

        brands = sorted({
            brand
            for brand, domain in brand_hits
        })

        add_evidence(
            evidence,
            "Brand Impersonation",
            "Brand reference on non-official domain",
            14,
            90,
            "SUSPICIOUS",
            "URL brand terms and registrable domain",
            "Brand-related term(s) appear outside their official domain: "
            + ", ".join(brands[:6]),
            "A recognizable brand name appearing in a URL controlled by another domain can indicate impersonation or credential-harvesting activity.",
            "HIGH"
        )

    # --------------------------------------------------------
    # 15. Excessive numeric content in host
    # --------------------------------------------------------

    if host:
        digit_ratio = sum(
            c.isdigit()
            for c in host
        ) / len(host)

        if (
            len(host) >= 15
            and digit_ratio >= 0.25
        ):
            add_evidence(
                evidence,
                "Domain Structure",
                "High numeric hostname content",
                6,
                70,
                "SUSPICIOUS",
                "Hostname character composition",
                f"Approximately {digit_ratio * 100:.0f}% of the hostname consists of digits.",
                "An unusually numeric hostname can be a supporting indicator of generated or deceptive domain structure.",
                "MEDIUM"
            )

    return evidence


class EnhancedPhishGuardEngine:
    """
    Wraps the original PhishGuard engine.

    Existing v2.2 URL, brand, TLS, and GUI behavior remains available.
    Additional local evidence is appended, and the final risk score is
    calculated once from the evidence list to avoid duplicate weighting.
    """

    def __init__(self):
        self.base_engine = BasePhishGuardEngine()

        # Preserve attributes expected by research harnesses.
        if hasattr(self.base_engine, "tls_engine"):
            self.tls_engine = self.base_engine.tls_engine

    def analyze(self, url):

        # If a test harness replaces our TLS engine, pass that change
        # into the original engine before analysis.
        if hasattr(self, "tls_engine"):
            try:
                self.base_engine.tls_engine = self.tls_engine
            except Exception:
                pass

        verdict = self.base_engine.analyze(url)

        additional = enhanced_local_evidence(url)

        verdict.evidence.extend(additional)

        # Calculate each evidence contribution once.
        risk = sum(
            item.score
            for item in verdict.evidence
        )

        # Preserve trust credit for exact official brand/domain match.
        if verdict.brand.get("official"):
            risk -= 25

        verdict.risk = max(
            0,
            min(100, int(round(risk)))
        )

        if verdict.risk >= BLOCK_MIN:
            verdict.decision = "BLOCK"
        elif verdict.risk >= WARN_MIN:
            verdict.decision = "WARN"
        else:
            verdict.decision = "ALLOW"

        # Rebuild concise explanation list from scored evidence.
        scored = sorted(
            [
                item
                for item in verdict.evidence
                if item.score > 0
            ],
            key=lambda item: item.score,
            reverse=True
        )

        verdict.reasons = [
            item.finding
            for item in scored[:8]
        ]

        return verdict


# Replace the engine used by the existing GUI.
pg.PhishGuardEngine = EnhancedPhishGuardEngine


def main():
    pg.main()


if __name__ == "__main__":
    main()
