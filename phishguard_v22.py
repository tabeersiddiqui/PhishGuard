import sys, ssl, socket, urllib.parse
import csv
import io
import os
import random
import zipfile
import urllib.request
from pathlib import Path
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Dict
from PySide6.QtWidgets import QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLineEdit, QPushButton, QLabel, QDialog, QTextEdit, QComboBox, QSystemTrayIcon, QMenu, QScrollArea
from PySide6.QtCore import Qt, QUrl
from PySide6.QtGui import QAction, QIcon, QPainter, QColor, QPixmap
from PySide6.QtWebEngineWidgets import QWebEngineView
try:
    import idna
except Exception:
    idna = None

APP_NAME = "PhishGuard v2.2"

KNOWN_BRANDS = {
    "paypal": ["paypal.com"], "microsoft": ["microsoft.com", "login.microsoftonline.com", "office.com", "outlook.com", "live.com"],
    "google": ["google.com", "accounts.google.com", "gmail.com"], "apple": ["apple.com", "icloud.com"],
    "amazon": ["amazon.com"], "bankofamerica": ["bankofamerica.com"], "chase": ["chase.com"],
    "wellsfargo": ["wellsfargo.com"], "github": ["github.com"], "linkedin": ["linkedin.com"],
    "facebook": ["facebook.com"], "instagram": ["instagram.com"], "netflix": ["netflix.com"],
    "docusign": ["docusign.com"], "irs": ["irs.gov"], "ssa": ["ssa.gov"], "usps": ["usps.com"],
    "fedex": ["fedex.com"], "ups": ["ups.com"], "coinbase": ["coinbase.com"], "binance": ["binance.com"]
}

SUSPICIOUS_KEYWORDS = {"login","secure","verify","verification","update","account","support","billing","alert","auth","recovery","signin","confirm","unlock","security","password","check","limited","suspend","suspended","restore","wallet","payment","invoice","refund","tax","delivery","tracking","claim","appeal","notice"}
SUSPICIOUS_TLDS = {"zip","top","click","shop","buzz","rest","work","support","gq","tk","info","icu","cyou","live","mom","monster","sbs","quest","bond"}


# ============================================================
# PHISHGUARD 1,000-SITE RESEARCH DATASET
# 500 legitimate domains + 500 verified phishing URLs
# ============================================================

DATASET_FILE = Path(__file__).with_name("phishguard_dataset_1000.csv")

TRANCO_URL = "https://tranco-list.eu/top-1m.csv.zip"

PHISHTANK_APP_KEY = os.environ.get(
    "PHISHTANK_APP_KEY",
    ""
).strip()

if PHISHTANK_APP_KEY:
    PHISHTANK_URL = (
        "http://data.phishtank.com/data/"
        + PHISHTANK_APP_KEY
        + "/online-valid.csv"
    )
else:
    PHISHTANK_URL = (
        "http://data.phishtank.com/data/online-valid.csv"
    )

RESEARCH_RANDOM_SEED = 4312026
LEGITIMATE_COUNT = 500
PHISHING_COUNT = 500


def research_download(url):
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent":
            "PhishGuard-Academic-Research/2.3"
        }
    )

    with urllib.request.urlopen(
        req,
        timeout=90
    ) as response:
        return response.read()


def collect_tranco_sites():
    print(
        "PhishGuard: collecting "
        "500 legitimate Tranco domains..."
    )

    raw = research_download(TRANCO_URL)

    with zipfile.ZipFile(
        io.BytesIO(raw)
    ) as archive:

        names = archive.namelist()

        if not names:
            raise RuntimeError(
                "Tranco archive was empty."
            )

        text = archive.read(
            names[0]
        ).decode(
            "utf-8",
            errors="replace"
        )

    candidates = []

    for row in csv.reader(
        io.StringIO(text)
    ):
        if len(row) < 2:
            continue

        domain = row[1].strip().lower()

        if not domain:
            continue

        if "." not in domain:
            continue

        candidates.append(domain)

        # Pull from a larger pool so the study
        # is not limited to exactly the first
        # 500 ranked domains.
        if len(candidates) >= 5000:
            break

    candidates = sorted(
        set(candidates)
    )

    if len(candidates) < LEGITIMATE_COUNT:
        raise RuntimeError(
            "Not enough Tranco domains "
            "were available."
        )

    rng = random.Random(
        RESEARCH_RANDOM_SEED
    )

    selected = rng.sample(
        candidates,
        LEGITIMATE_COUNT
    )

    return [
        {
            "url": "https://" + domain,
            "ground_truth": "LEGITIMATE",
            "source": "Tranco",
            "source_id": ""
        }
        for domain in selected
    ]


def collect_phishtank_sites():
    print(
        "PhishGuard: collecting "
        "500 verified phishing URLs..."
    )

    raw = research_download(
        PHISHTANK_URL
    )

    text = raw.decode(
        "utf-8",
        errors="replace"
    )

    reader = csv.DictReader(
        io.StringIO(text)
    )

    candidates = []

    for row in reader:

        url = (
            row.get("url")
            or ""
        ).strip()

        verified = (
            row.get("verified")
            or ""
        ).strip().lower()

        online = (
            row.get("online")
            or ""
        ).strip().lower()

        if not url:
            continue

        if verified not in {
            "yes", "y", "true", "1"
        }:
            continue

        if online not in {
            "yes", "y", "true", "1"
        }:
            continue

        try:
            parsed = urllib.parse.urlparse(
                url
            )
            host = parsed.hostname
        except Exception:
            host = None

        if not host:
            continue

        candidates.append(
            {
                "url": url,
                "ground_truth": "PHISHING",
                "source": "PhishTank",
                "source_id": (
                    row.get("phish_id")
                    or ""
                ).strip()
            }
        )

    # Remove duplicate URLs
    unique = {}

    for item in candidates:
        unique[item["url"]] = item

    candidates = list(
        unique.values()
    )

    if len(candidates) < PHISHING_COUNT:
        raise RuntimeError(
            "PhishTank supplied only "
            + str(len(candidates))
            + " usable phishing URLs; "
            "500 are required."
        )

    rng = random.Random(
        RESEARCH_RANDOM_SEED
    )

    return rng.sample(
        candidates,
        PHISHING_COUNT
    )


def build_research_dataset():

    legitimate = collect_tranco_sites()
    phishing = collect_phishtank_sites()

    records = legitimate + phishing

    rng = random.Random(
        RESEARCH_RANDOM_SEED
    )

    rng.shuffle(records)

    with DATASET_FILE.open(
        "w",
        newline="",
        encoding="utf-8"
    ) as f:

        writer = csv.DictWriter(
            f,
            fieldnames=[
                "sample_id",
                "url",
                "ground_truth",
                "source",
                "source_id"
            ]
        )

        writer.writeheader()

        for index, item in enumerate(
            records,
            1
        ):

            writer.writerow(
                {
                    "sample_id":
                    "PG-" + str(index).zfill(4),

                    "url":
                    item["url"],

                    "ground_truth":
                    item["ground_truth"],

                    "source":
                    item["source"],

                    "source_id":
                    item["source_id"]
                }
            )

    print()
    print(
        "PhishGuard research dataset created."
    )
    print(
        "500 legitimate + "
        "500 phishing = 1,000 sites."
    )
    print(
        "Saved as:",
        DATASET_FILE
    )

    return records


def load_research_dataset():

    records = []

    # --------------------------------------------------------
    # If the dataset already exists, DO NOT download a new one.
    # This freezes the exact 1,000 observations for research.
    # --------------------------------------------------------

    if DATASET_FILE.exists():

        try:
            with DATASET_FILE.open(
                "r",
                newline="",
                encoding="utf-8"
            ) as f:

                reader = csv.DictReader(f)

                for row in reader:

                    if row.get("url"):
                        records.append(
                            {
                                "url":
                                row["url"],

                                "ground_truth":
                                row.get(
                                    "ground_truth",
                                    ""
                                ),

                                "source":
                                row.get(
                                    "source",
                                    ""
                                ),

                                "source_id":
                                row.get(
                                    "source_id",
                                    ""
                                )
                            }
                        )

            legitimate_total = sum(
                1
                for r in records
                if r["ground_truth"]
                == "LEGITIMATE"
            )

            phishing_total = sum(
                1
                for r in records
                if r["ground_truth"]
                == "PHISHING"
            )

            if (
                legitimate_total == 500
                and phishing_total == 500
                and len(records) == 1000
            ):
                print(
                    "PhishGuard: loaded frozen "
                    "1,000-site research dataset."
                )
                return records

            print(
                "Existing dataset was incomplete. "
                "Rebuilding it..."
            )

        except Exception as e:
            print(
                "Could not read existing dataset:",
                e
            )

    return build_research_dataset()


try:

    RESEARCH_DATASET = (
        load_research_dataset()
    )

    DEMO_SITES = [
        record["url"]
        for record in RESEARCH_DATASET
    ]

except Exception as e:

    print()
    print(
        "WARNING: The 1,000-site research "
        "dataset could not be downloaded."
    )
    print(e)
    print(
        "PhishGuard will start with the "
        "original demonstration sites."
    )

    DEMO_SITES = [
        "paypal.com",
        "microsoft.com",
        "google.com",
        "apple.com",
        "amazon.com",
        "chase.com",

        "paypal-secure-verification.com",
        "paypa1.com",
        "paypal-account-restore.net",
        "secure-paypal-billing-alert.com",

        "micr0soft-login.com",
        "microsoft365-password-reset-support.com",
        "office-login-verification.net",

        "g00gle-accounts.net",
        "google-account-recovery-check.com",

        "icloudverify-security.com",
        "appleid-verify-security.com",

        "amazon-order-refund-support.com",
        "amazon-prime-billing-update.net",

        "bankofarnerica-alert.com",
        "bankofamerica-secure-message-center.com",

        "chase-secure-login.net",
        "chase-account-unlock-support.com",

        "wellsfarg0-update.com",
        "github-auth-check.com",
        "linkedin-verification.net",

        "faceboook-login-help.com",
        "instagram-copyright-appeal.com",
        "netflix-payment-update-alert.com",

        "docusign-secure-envelope-review.com",
        "irs-tax-refund-claim.com",
        "ssa-benefits-verification.com",

        "usps-delivery-fee-confirm.com",
        "fedex-tracking-redelivery.com",
        "ups-package-hold-confirm.com",

        "coinbase-wallet-verify.com",
        "binance-security-wallet-alert.com",

        "xn--pple-43d.com",
        "xn--microsft-03a.com"
    ]

# ============================================================
# END 1,000-SITE RESEARCH DATASET
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
    reasons: List[str] = field(default_factory=list)
    validations: List[str] = field(default_factory=list)
    tested: List[str] = field(default_factory=list)
    evidence: List[EvidenceItem] = field(default_factory=list)
    tls: Dict = field(default_factory=dict)
    brand: Dict = field(default_factory=dict)

def create_icon(color="#111827"):
    pix = QPixmap(64,64); pix.fill(Qt.GlobalColor.transparent)
    p = QPainter(pix); p.setRenderHint(QPainter.RenderHint.Antialiasing)
    p.setBrush(QColor(color)); p.setPen(Qt.PenStyle.NoPen); p.drawRoundedRect(4,4,56,56,12,12)
    p.setBrush(QColor("white")); p.drawEllipse(18,14,28,20); p.drawRect(21,28,22,18); p.end()
    return QIcon(pix)

def idna_to_ascii(host):
    host=(host or "").strip().lower().rstrip(".")
    try: return idna.encode(host).decode("ascii") if idna else host.encode("idna").decode("ascii")
    except Exception: return host

def idna_to_unicode(host):
    host=(host or "").strip().lower().rstrip(".")
    try: return idna.decode(host) if idna else host.encode("ascii").decode("idna")
    except Exception: return host

def normalize_host(host):
    host=idna_to_ascii(host)
    return host[4:] if host.startswith("www.") else host

def registrable_domain(host):
    host=normalize_host(host); parts=host.split(".")
    if len(parts)<=2: return host
    if len(parts)>=3 and parts[-2] in {"co","com","org","net"}: return ".".join(parts[-3:])
    return ".".join(parts[-2:])

def second_level_label(host):
    reg=registrable_domain(host)
    return reg.split(".")[0] if reg else ""

def is_ip_host(host):
    parts=host.split(".")
    if len(parts)!=4: return False
    try: return all(0<=int(x)<=255 for x in parts)
    except Exception: return False

def normalize_for_typos(label):
    s=label.lower()
    for a,b in [("0","o"),("1","l"),("3","e"),("4","a"),("5","s"),("7","t"),("rn","m"),("vv","w"),("cl","d")]:
        s=s.replace(a,b)
    return s

def levenshtein(a,b):
    if a==b: return 0
    if not a: return len(b)
    if not b: return len(a)
    prev=list(range(len(b)+1))
    for i,ca in enumerate(a,1):
        cur=[i]
        for j,cb in enumerate(b,1):
            cur.append(min(cur[j-1]+1, prev[j]+1, prev[j-1]+(ca!=cb)))
        prev=cur
    return prev[-1]

class TLSEngine:
    def analyze(self, host):
        result={"validated":False,"subject":"Not validated","issuer":"Not validated","days_left":None,"error":None,"score":0,"tested":"TLS certificate validation, issuer, subject, and expiration window"}
        host=normalize_host(host)
        if not host:
            result["error"]="No hostname found"; result["score"]=35; return result
        try:
            ctx=ssl.create_default_context()
            with socket.create_connection((host,443),timeout=4) as sock:
                with ctx.wrap_socket(sock,server_hostname=host) as ssock:
                    cert=ssock.getpeercert(); result["validated"]=True
                    def flat(parts): return ", ".join(f"{k}={v}" for group in parts for k,v in group)
                    result["subject"]=flat(cert.get("subject",())) or "Unavailable"
                    result["issuer"]=flat(cert.get("issuer",())) or "Unavailable"
                    if cert.get("notAfter"):
                        exp=datetime.strptime(cert["notAfter"],"%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                        result["days_left"]=int((exp-datetime.now(timezone.utc)).total_seconds()//86400)
                    if result["days_left"] is not None and result["days_left"]<0: result["score"]=35
                    elif result["days_left"] is not None and result["days_left"]<=14: result["score"]=15
        except Exception as e:
            result["error"]=str(e); result["score"]=30
        return result

class BrandEngine:
    def analyze(self, host):
        host=normalize_host(host); reg=registrable_domain(host); obs=normalize_for_typos(second_level_label(host))
        for brand,domains in KNOWN_BRANDS.items():
            for d in domains:
                if reg==registrable_domain(d):
                    return {"official":True,"brand":brand,"official_domain":registrable_domain(d),"distance":0,"score":0,"reason":f"The domain matches the known official domain for {brand}.","tested":"Exact official-domain match against known brand domain list"}
        best={"official":False,"brand":"unknown","official_domain":"unknown","distance":None,"score":0,"reason":"No strong brand similarity detected.","tested":"Brand impersonation, typosquatting, character substitution, and embedded brand-name comparison"}
        for brand,domains in KNOWN_BRANDS.items():
            for d in domains:
                official=registrable_domain(d); target=normalize_for_typos(second_level_label(d)); dist=levenshtein(obs,target)
                score=0; reason=None
                if obs==target and reg!=official: score=95; reason=f"The domain label appears to mimic {brand} using character substitution."
                elif target in obs and reg!=official: score=85; reason=f"The domain embeds the {brand} brand name inside a non-official domain."
                elif dist==1 and len(target)>=5: score=88; reason=f"The domain is one character away from the official {brand} domain label."
                elif dist==2 and len(target)>=5: score=75; reason=f"The domain is a close typo-style variation of the official {brand} domain label."
                elif dist==3 and len(target)>=7: score=60; reason=f"The domain is a moderate lexical variation of the official {brand} domain label."
                if score>best["score"]:
                    best={"official":False,"brand":brand,"official_domain":official,"distance":dist,"score":score,"reason":reason,"tested":"Brand impersonation, typosquatting, character substitution, and embedded brand-name comparison"}
        return best

class URLEngine:
    def analyze(self, url, host, unicode_host):
        ev=[]; parsed=urllib.parse.urlparse(url); label=second_level_label(host)
        def add(cat,test,score,conf,status,tested,finding,why,severity):
            ev.append(EvidenceItem(cat,test,score,conf,status,tested,finding,why,severity))
        if parsed.scheme!="https": add("Transport Security","HTTPS Check",18,80,"Failed","Tested whether the URL uses HTTPS.","The URL does not use HTTPS.","Without HTTPS, credentials and session data may be exposed or manipulated.","high")
        if is_ip_host(host): add("Domain Identity","Raw IP Address Check",30,90,"Failed","Tested whether the destination uses a named domain or raw IP address.","The URL uses a raw IP address.","Phishing pages often hide behind raw IP addresses because there is no clear organization identity.","high")
        if "xn--" in host: add("International Domain","IDN/Punycode Check",22,90,"Flagged","Tested whether the domain uses internationalized-domain punycode encoding.",f"The ASCII hostname contains punycode. Unicode form: {unicode_host}","Internationalized domains are valid, but attackers can use visually similar characters to impersonate trusted brands.","high")
        if "@" in url: add("URL Structure","@ Symbol Check",20,90,"Failed","Tested whether the URL contains an @ symbol.","The URL contains @, which can disguise the real destination.","Anything before @ may look trusted while the browser actually navigates elsewhere.","high")
        if host.count(".")>=3: add("URL Structure","Subdomain Depth Check",12,70,"Flagged","Tested whether the hostname has unusually deep subdomain nesting.","The host contains several subdomain levels.","Attackers often place trusted brand names in subdomains while the real registered domain is unrelated.","medium")
        if host.count("-")>=2: add("Domain Structure","Hyphen Density Check",10,65,"Flagged","Tested whether the domain contains multiple hyphens.","The domain contains multiple hyphens.","Phishing domains often use hyphenated phrases like secure-login or account-update to appear legitimate.","medium")
        tld=host.split(".")[-1] if "." in host else ""
        if tld in SUSPICIOUS_TLDS: add("Top-Level Domain","Suspicious TLD Check",15,70,"Flagged","Tested the domain extension against a suspicious TLD list.",f"The domain uses .{tld}, which is on the suspicious TLD list.","Some low-cost or frequently abused TLDs are commonly used in disposable phishing infrastructure.","medium")
        hits=sorted([kw for kw in SUSPICIOUS_KEYWORDS if kw in host])
        if hits: add("Phishing Language","Lure Keyword Check",min(18,4*len(hits)),75,"Flagged","Tested whether the hostname contains urgency or account-action words.","Detected lure keywords: "+", ".join(hits),"Phishing domains often use words like verify, secure, account, billing, refund, or password to pressure users into action.","medium")
        if sum(ch.isdigit() for ch in label)>=1 and not is_ip_host(host): add("Typosquatting","Digit Substitution Check",8,65,"Flagged","Tested whether the domain label uses numbers that resemble letters.","The domain label contains numeric substitutions.","Attackers often replace letters with numbers, such as 0 for o or 1 for l, to imitate trusted domains.","medium")
        return ev

class RiskEngine:
    def calculate(self,evidence,brand,tls):
        risk=sum(i.score for i in evidence)
        if brand.get("official"): risk-=25
        elif brand.get("score",0)>=80: risk+=42
        elif brand.get("score",0)>=65: risk+=28
        elif brand.get("score",0)>=50: risk+=16
        risk+=tls.get("score",0)
        return max(0,min(100,risk))
    def decision(self,risk):
        return "BLOCK" if risk>=70 else "WARN" if risk>=45 else "ALLOW"

class PhishGuardEngine:
    def __init__(self):
        self.url_engine=URLEngine(); self.brand_engine=BrandEngine(); self.tls_engine=TLSEngine(); self.risk_engine=RiskEngine()
    def analyze(self,url):
        if not urllib.parse.urlparse(url).scheme: url="https://"+url
        parsed=urllib.parse.urlparse(url); host=normalize_host(parsed.hostname or ""); unicode_host=idna_to_unicode(host); domain=registrable_domain(host)
        tested=["URL syntax and hostname parsing","HTTPS transport presence","Raw IP address detection","International domain / IDNA punycode detection","Suspicious top-level domain comparison","Suspicious phishing keyword detection","Hyphen density and subdomain-depth analysis","Digit substitution and typosquatting indicators","Known-brand impersonation comparison","Levenshtein distance similarity analysis","TLS certificate validation and expiration check","Final weighted risk score calculation"]
        if not host:
            item=EvidenceItem("URL Parsing","Hostname Parse Check",100,100,"Failed","Tested whether a valid hostname could be extracted.","The hostname could not be parsed.","Without a valid hostname, the destination cannot be safely evaluated.","critical")
            return Verdict(url,"","", "",100,"BLOCK",[item.finding],[],tested,[item],{}, {})
        evidence=self.url_engine.analyze(url,host,unicode_host); brand=self.brand_engine.analyze(host); tls=self.tls_engine.analyze(host)
        if not brand.get("official") and brand.get("score",0)>=50:
            evidence.append(EvidenceItem("Brand Impersonation","Known Brand Similarity Check",brand["score"],90,"Failed",brand["tested"],brand["reason"],f"The observed domain is being compared against the official reference domain {brand.get('official_domain')}. Close similarity can indicate typosquatting or credential-harvesting impersonation.","high"))
        if tls.get("score",0)>0:
            evidence.append(EvidenceItem("TLS Certificate","Certificate Validation Check",tls["score"],75,"Flagged",tls["tested"],tls.get("error") or "TLS certificate is expired, near expiration, or could not be fully validated.","A missing or abnormal TLS certificate does not prove phishing by itself, but it weakens trust when combined with other indicators.","medium"))
        risk=self.risk_engine.calculate(evidence,brand,tls); decision=self.risk_engine.decision(risk)
        reasons=[f"{i.test_name}: {i.finding} Score impact: +{i.score}. Reason: {i.why_it_matters}" for i in evidence] or ["No major phishing indicators detected. The URL passed the local structural, brand, TLS, and keyword checks."]
        validations=[]
        if parsed.scheme=="https": validations.append("HTTPS transport was present.")
        if not is_ip_host(host): validations.append("The host is not a raw IP address.")
        if "@" not in url: validations.append("No @ symbol was present in the URL.")
        if host.count(".")<3: validations.append("Hostname depth was not unusually high.")
        if host.count("-")<2: validations.append("The hostname did not contain excessive hyphenation.")
        if brand.get("official"): validations.append(brand["reason"])
        elif brand.get("score",0)<50: validations.append("No strong known-brand impersonation signal was detected.")
        if tls.get("validated"): validations.append("TLS certificate successfully validated.")
        return Verdict(url,host,unicode_host,domain,risk,decision,reasons,validations,tested,evidence,tls,brand)



class ThreatDialog(QDialog):
    def __init__(self, verdict, parent=None):
        super().__init__(parent)

        safe = verdict.decision == "ALLOW"

        bg = "#061b0b" if safe else "#180000"
        panel = "#0e3215" if safe else "#2b0000"
        border = "#2ecc71" if safe else "#ff4d4d"
        banner = "#148f3d" if safe else "#b00000"
        title = "✓ TRUSTED SITE CHECK PASSED" if safe else "⚠ UNTRUSTED SITE DETECTED"
        status_color = "#d1fae5" if safe else "#fee2e2"
        heading_color = "#d1fae5" if safe else "#fee2e2"

        self.setWindowTitle("PhishGuard Site Analysis")
        self.resize(1120, 820)
        self.setMinimumSize(950, 680)

        self.setStyleSheet(f"""
            QDialog {{
                background-color: {bg};
                font-family: Arial;
            }}
            QLabel#banner {{
                color: white;
                background-color: {banner};
                font-size: 32px;
                font-weight: 900;
                padding: 18px;
                border: 3px solid {border};
                border-radius: 14px;
            }}
            QLabel#status {{
                color: {status_color};
                font-size: 26px;
                font-weight: 900;
                padding: 10px;
            }}
            QLabel#section {{
                color: {heading_color};
                font-size: 21px;
                font-weight: 900;
                padding-top: 10px;
            }}
            QLabel#meta {{
                color: white;
                font-size: 18px;
                font-weight: 700;
                padding: 12px;
            }}
            QTextEdit {{
                background-color: {panel};
                color: white;
                font-size: 17px;
                font-weight: 600;
                border: 2px solid {border};
                border-radius: 10px;
                padding: 12px;
            }}
            QPushButton {{
                background-color: {banner};
                color: white;
                font-size: 18px;
                font-weight: 800;
                padding: 10px 30px;
                border-radius: 9px;
            }}
            QScrollArea {{
                border: none;
                background-color: {bg};
            }}
            QScrollBar:vertical {{
                background: {panel};
                width: 16px;
            }}
            QScrollBar::handle:vertical {{
                background: {border};
                border-radius: 8px;
            }}
        """)

        outer = QVBoxLayout(self)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)

        content = QWidget()
        content.setStyleSheet(f"background-color: {bg};")
        layout = QVBoxLayout(content)
        layout.setSpacing(12)

        banner_label = QLabel(title)
        banner_label.setObjectName("banner")
        banner_label.setAlignment(Qt.AlignmentFlag.AlignCenter)

        status = QLabel(f"{verdict.decision} | Risk Score: {verdict.risk}/100")
        status.setObjectName("status")
        status.setAlignment(Qt.AlignmentFlag.AlignCenter)

        meta = QLabel(
            f"URL: {verdict.url}\n"
            f"ASCII Host: {verdict.host}\n"
            f"Unicode Host: {verdict.unicode_host}\n"
            f"Domain: {verdict.domain}\n"
            f"Likely Target Brand: {verdict.brand.get('brand', 'unknown')}\n"
            f"Reference Official Domain: {verdict.brand.get('official_domain', 'unknown')}"
        )
        meta.setObjectName("meta")
        meta.setWordWrap(True)

        layout.addWidget(banner_label)
        layout.addWidget(status)
        layout.addWidget(meta)

        def add_box(title, text, height):
            label = QLabel(title)
            label.setObjectName("section")

            box = QTextEdit()
            box.setReadOnly(True)
            box.setPlainText(text)
            box.setMinimumHeight(height)
            box.setMaximumHeight(height)

            layout.addWidget(label)
            layout.addWidget(box)

        add_box(
            "What PhishGuard Tested",
            "\n".join(f"• {t}" for t in verdict.tested),
            135
        )

        add_box(
            "Detailed Risk Reasoning",
            "\n".join(f"• {r}" for r in verdict.reasons),
            190
        )

        add_box(
            "Validated Signals",
            "\n".join(f"• {v}" for v in verdict.validations),
            135
        )

        add_box(
            "Detection Engine Evidence",
            "\n\n".join(
                f"[{e.category}] {e.test_name}\n"
                f"Status: {e.status}\n"
                f"Score Impact: +{e.score}\n"
                f"Confidence: {e.confidence}%\n"
                f"What was tested: {e.what_was_tested}\n"
                f"Finding: {e.finding}\n"
                f"Why it matters: {e.why_it_matters}"
                for e in verdict.evidence
            ) or "No major threat evidence recorded.",
            240
        )

        tls = verdict.tls or {}
        add_box(
            "TLS Certificate Assessment",
            f"Validated: {'Yes' if tls.get('validated') else 'No'}\n"
            f"Subject: {tls.get('subject', 'Unavailable')}\n"
            f"Issuer: {tls.get('issuer', 'Unavailable')}\n"
            f"Days Until Expiry: {tls.get('days_left', 'Unavailable')}\n"
            f"Error: {tls.get('error') or 'None'}",
            145
        )

        close = QPushButton("Close")
        close.clicked.connect(self.accept)
        layout.addWidget(close, alignment=Qt.AlignmentFlag.AlignCenter)

        scroll.setWidget(content)
        outer.addWidget(scroll)

class Browser(QMainWindow):
    def __init__(self):
        super().__init__(); self.engine=PhishGuardEngine(); self.setWindowTitle(APP_NAME); self.resize(1380,920)
        self.view=QWebEngineView(); self.url_bar=QLineEdit(); self.url_bar.setPlaceholderText("Enter a URL or select a demo site"); self.url_bar.returnPressed.connect(self.go)
        go=QPushButton("Go"); go.clicked.connect(self.go); analyze=QPushButton("Analyze Only"); analyze.clicked.connect(self.analyze_current)
        self.demo=QComboBox()
        self.demo.addItem("Select a research site")

        # Keep the GUI compact even when the stored phishing URL is very long.
        # The complete URL is stored as hidden item data and is still analyzed.
        for index, site in enumerate(DEMO_SITES, 1):
            try:
                display_host = urllib.parse.urlparse(
                    site if "://" in site else "https://" + site
                ).hostname or site
            except Exception:
                display_host = site

            short_label = f"PG-{index:04d} | {display_host[:55]}"
            self.demo.addItem(short_label, site)

        self.demo.setSizeAdjustPolicy(
            QComboBox.SizeAdjustPolicy.AdjustToMinimumContentsLengthWithIcon
        )
        self.demo.setMinimumContentsLength(32)
        self.demo.setMaximumWidth(750)
        self.demo.view().setTextElideMode(Qt.TextElideMode.ElideRight)

        self.demo.currentIndexChanged.connect(self.load_demo_selection)
        self.status=QLabel("Ready"); self.status.setStyleSheet("font-size:16px;padding:8px;"); self.status.setWordWrap(True)
        header=QLabel("PhishGuard v2.2"); header.setAlignment(Qt.AlignmentFlag.AlignCenter); header.setStyleSheet("background:#111827;color:white;font-size:34px;font-weight:900;padding:18px;border-radius:12px;")
        sub=QLabel("Accessible real-time phishing analysis with detailed explainable scoring"); sub.setAlignment(Qt.AlignmentFlag.AlignCenter); sub.setStyleSheet("font-size:17px;color:#374151;padding:6px;")
        top=QHBoxLayout(); top.addWidget(self.url_bar,1); top.addWidget(go); top.addWidget(analyze)
        demos=QHBoxLayout(); demos.addWidget(QLabel("Demo Sites:")); demos.addWidget(self.demo,1)
        layout=QVBoxLayout(); layout.addWidget(header); layout.addWidget(sub); layout.addLayout(top); layout.addLayout(demos); layout.addWidget(self.view,1); layout.addWidget(self.status)
        w=QWidget(); w.setLayout(layout); self.setCentralWidget(w)

    def card(self,title,body,accent,border,bg):
        return f"<div style='background:{bg};border:4px solid {border};border-radius:18px;padding:24px;margin:22px 0;'><h2 style='color:{accent};font-size:32px;margin-top:0;font-weight:900;'>{title}</h2><div style='font-size:21px;line-height:1.55;font-weight:600;'>{body}</div></div>"

    def render_analysis_page(self, v):
        safe=v.decision=="ALLOW"; bg="#ecfdf3" if safe else "#fff1f2"; accent="#15803d" if safe else "#b00000"; border="#22c55e" if safe else "#ff4d4d"; title="TRUSTED SITE CHECK PASSED" if safe else "UNTRUSTED SITE DETECTED"
        rec="This site passed the local PhishGuard checks. Continue carefully and only enter credentials if you intentionally navigated to this site." if safe else "Do NOT enter usernames, passwords, payment details, recovery codes, or personal information on this site."
        def ul(items): return "<ul>"+"".join(f"<li>{x}</li>" for x in items)+"</ul>"
        ev="".join(f"<div style='border:3px solid {border};border-radius:14px;padding:16px;margin:14px 0;background:white;'><h3 style='color:{accent};font-size:25px;margin:0;font-weight:900;'>{e.category}: {e.test_name}</h3><p><b>Status:</b> {e.status}</p><p><b>Score Impact:</b> +{e.score}</p><p><b>Confidence:</b> {e.confidence}%</p><p><b>What was tested:</b> {e.what_was_tested}</p><p><b>Finding:</b> {e.finding}</p><p><b>Why it matters:</b> {e.why_it_matters}</p></div>" for e in v.evidence) or "<p>No major threat evidence recorded.</p>"
        html=f"""
        <html><body style='background:{bg};font-family:Arial,sans-serif;padding:40px;color:#111827;'>
        <div style='max-width:1180px;margin:auto;background:white;border:6px solid {border};border-radius:24px;padding:42px;'>
        <h1 style='color:{accent};font-size:58px;text-align:center;font-weight:900;'>{title}</h1>
        <h2 style='font-size:36px;text-align:center;font-weight:900;'>{v.decision} | Risk Score: {v.risk}/100</h2>
        {self.card("Site Details",f"<p><b>URL:</b> {v.url}</p><p><b>ASCII Host:</b> {v.host}</p><p><b>Unicode Host:</b> {v.unicode_host}</p><p><b>Domain:</b> {v.domain}</p><p><b>Likely Target Brand:</b> {v.brand.get('brand','unknown')}</p><p><b>Official Reference Domain:</b> {v.brand.get('official_domain','unknown')}</p>",accent,border,bg)}
        {self.card("Recommendation",f"<p>{rec}</p>",accent,border,bg)}
        {self.card("What PhishGuard Tested",ul(v.tested),accent,border,bg)}
        {self.card("Detailed Risk Reasoning",ul(v.reasons),accent,border,bg)}
        {self.card("Validated Signals",ul(v.validations),accent,border,bg)}
        {self.card("Detection Engine Evidence",ev,accent,border,bg)}
        </div></body></html>
        """
        self.view.setHtml(html)

    def run_analysis(self,url,load_if_safe=True):
        v=self.engine.analyze(url); self.url_bar.setText(v.url)
        color="#15803d" if v.decision=="ALLOW" else "#b00000"; self.status.setStyleSheet(f"font-size:16px;padding:8px;color:{color};font-weight:bold;"); self.status.setText(f"{v.decision} | Risk {v.risk}/100 | Host: {v.host}")
        ThreatDialog(v,self).exec()
        self.view.setUrl(QUrl(v.url)) if v.decision=="ALLOW" and load_if_safe else self.render_analysis_page(v)
    def go(self):
        if self.url_bar.text().strip(): self.run_analysis(self.url_bar.text().strip(),True)
    def analyze_current(self):
        if self.url_bar.text().strip(): self.run_analysis(self.url_bar.text().strip(),False)
    def load_demo_selection(self, index):
        if index <= 0:
            return

        url = self.demo.itemData(index)

        if url:
            self.url_bar.setText(url)
            self.run_analysis(url, False)

class TrayApp:
    def __init__(self,app):
        self.app=app; self.browser=Browser(); self.tray=QSystemTrayIcon(create_icon("#111827")); self.tray.setToolTip(APP_NAME)
        menu=QMenu(); open_a=QAction("Open PhishGuard"); open_a.triggered.connect(self.show_browser); quit_a=QAction("Quit"); quit_a.triggered.connect(app.quit)
        menu.addAction(open_a); menu.addSeparator(); menu.addAction(quit_a); self.tray.setContextMenu(menu); self.tray.activated.connect(self.on_click); self.tray.show()
    def show_browser(self): self.browser.show(); self.browser.raise_(); self.browser.activateWindow()
    def on_click(self,reason):
        if reason==QSystemTrayIcon.ActivationReason.Trigger: self.show_browser()

def main():
    app=QApplication(sys.argv); app.setApplicationName(APP_NAME); app.setWindowIcon(create_icon("#111827")); app.setQuitOnLastWindowClosed(False)
    tray=TrayApp(app); tray.show_browser(); sys.exit(app.exec())

if __name__=="__main__":
    main()
