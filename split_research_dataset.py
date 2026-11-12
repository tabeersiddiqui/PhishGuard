#!/usr/bin/env python3

import csv
import random
import urllib.parse
from collections import defaultdict
from pathlib import Path

import tldextract


BASE = Path(__file__).resolve().parent
INPUT = BASE / "phishguard_dataset_1000.csv"

DEV = BASE / "phishguard_dataset_development.csv"
VAL = BASE / "phishguard_dataset_validation.csv"
FINAL = BASE / "phishguard_dataset_final_untouched.csv"

SEED = 4312026

_extract = tldextract.TLDExtract(
    suffix_list_urls=None
)


def domain_group(url):

    try:
        host = (
            urllib.parse.urlsplit(url).hostname
            or ""
        ).lower()
    except Exception:
        return url

    ext = _extract(host)

    if ext.domain and ext.suffix:
        return (
            f"{ext.domain}.{ext.suffix}"
        )

    return host or url


def load():

    with INPUT.open(
        "r",
        newline="",
        encoding="utf-8"
    ) as f:
        rows = list(
            csv.DictReader(f)
        )

    if len(rows) != 1000:
        raise SystemExit(
            f"Expected 1000 observations; found {len(rows)}."
        )

    return rows


def grouped_split(class_rows, rng):

    groups = defaultdict(list)

    for row in class_rows:
        groups[
            domain_group(row["url"])
        ].append(row)

    grouped = list(
        groups.values()
    )

    rng.shuffle(grouped)

    target_dev = int(
        len(class_rows) * 0.60
    )

    target_val = int(
        len(class_rows) * 0.20
    )

    dev = []
    val = []
    final = []

    for group in grouped:

        if len(dev) < target_dev:
            dev.extend(group)

        elif len(val) < target_val:
            val.extend(group)

        else:
            final.extend(group)

    return dev, val, final


def write_file(path, rows, fieldnames):

    with path.open(
        "w",
        newline="",
        encoding="utf-8"
    ) as f:

        writer = csv.DictWriter(
            f,
            fieldnames=fieldnames
        )

        writer.writeheader()
        writer.writerows(rows)


def counts(rows):

    legitimate = sum(
        row["ground_truth"].upper()
        == "LEGITIMATE"
        for row in rows
    )

    phishing = sum(
        row["ground_truth"].upper()
        == "PHISHING"
        for row in rows
    )

    return legitimate, phishing


def main():

    rows = load()

    fieldnames = list(
        rows[0].keys()
    )

    legit = [
        row for row in rows
        if row["ground_truth"].upper()
        == "LEGITIMATE"
    ]

    phishing = [
        row for row in rows
        if row["ground_truth"].upper()
        == "PHISHING"
    ]

    rng = random.Random(SEED)

    l_dev, l_val, l_final = grouped_split(
        legit,
        rng
    )

    p_dev, p_val, p_final = grouped_split(
        phishing,
        rng
    )

    development = l_dev + p_dev
    validation = l_val + p_val
    final = l_final + p_final

    rng.shuffle(development)
    rng.shuffle(validation)
    rng.shuffle(final)

    write_file(
        DEV,
        development,
        fieldnames
    )

    write_file(
        VAL,
        validation,
        fieldnames
    )

    write_file(
        FINAL,
        final,
        fieldnames
    )

    print()
    print("=" * 72)
    print("PHISHGUARD RESEARCH DATASET SPLIT")
    print("=" * 72)

    for name, data, path in [
        ("DEVELOPMENT", development, DEV),
        ("VALIDATION", validation, VAL),
        ("FINAL / UNTOUCHED", final, FINAL)
    ]:

        legitimate, phish = counts(data)

        print(
            f"{name:18s}: "
            f"{len(data):4d} total | "
            f"{legitimate:3d} legitimate | "
            f"{phish:3d} phishing"
        )

        print(
            f"                    {path.name}"
        )

    print()
    print(
        "IMPORTANT: Do not inspect or run the FINAL / UNTOUCHED "
        "dataset while tuning PhishGuard."
    )
    print("=" * 72)


if __name__ == "__main__":
    main()
