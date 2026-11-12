from pathlib import Path
import re

FILE = Path("phishguard_v22.py")
BACKUP = Path("phishguard_v22_before_1000_sites.py")

if not FILE.exists():
    raise SystemExit(
        "\nERROR: phishguard_v22.py was not found.\n"
        "Make sure you are inside ~/phishguard_v22\n"
    )

source = FILE.read_text(encoding="utf-8")

# ------------------------------------------------------------
# BACK UP THE WORKING VERSION FIRST
# ------------------------------------------------------------
if not BACKUP.exists():
    BACKUP.write_text(source, encoding="utf-8")
    print("Backup created:", BACKUP)

# ------------------------------------------------------------
# ADD STANDARD-LIBRARY IMPORTS
# Nothing else about your PySide6 application is changed.
# ------------------------------------------------------------
old_import = "import sys, ssl, socket, urllib.parse"

new_import = """import sys, ssl, socket, urllib.parse
import csv
import io
import os
import random
import zipfile
import urllib.request
from pathlib import Path"""

if old_import in source and "import zipfile" not in source:
    source = source.replace(old_import, new_import, 1)

# ------------------------------------------------------------
# RESEARCH DATASET CODE
#
# 500 legitimate domains: Tranco
# 500 verified online phishing URLs: PhishTank
#
# Dataset is downloaded ONCE and cached locally.
# After that, PhishGuard reuses the same frozen CSV.
# ------------------------------------------------------------

dataset_code = r'''
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
'''

# ------------------------------------------------------------
# REPLACE ONLY THE OLD DEMO_SITES LIST.
#
# Everything after it — including EvidenceItem, RiskEngine,
# ThreatDialog, ALLOW/BLOCK messages, colors, Browser,
# TrayApp, etc. — remains untouched.
# ------------------------------------------------------------

pattern = re.compile(
    r'DEMO_SITES\s*=\s*\[.*?\]\s*(?=@dataclass)',
    re.DOTALL
)

match = pattern.search(source)

if not match:
    # Maybe this script was already run.
    if "PHISHGUARD 1,000-SITE RESEARCH DATASET" in source:
        print(
            "The 1,000-site dataset code "
            "already appears to be installed."
        )
    else:
        raise SystemExit(
            "\nERROR: Could not find the original "
            "DEMO_SITES block.\n"
            "Your working file was NOT changed.\n"
        )
else:
    source = (
        source[:match.start()]
        + dataset_code
        + "\n"
        + source[match.end():]
    )

    FILE.write_text(
        source,
        encoding="utf-8"
    )

    print()
    print(
        "SUCCESS: phishguard_v22.py updated."
    )
    print(
        "Your original BLOCK and ALLOW "
        "interface code was not changed."
    )

print()
print(
    "Starting PhishGuard..."
)
