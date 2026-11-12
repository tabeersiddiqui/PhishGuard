#!/usr/bin/env python3

import csv
import json
import time
from pathlib import Path

import phishguard_v22 as pg

try:
    import psutil
except ImportError:
    psutil = None


BASE = Path(__file__).resolve().parent
DATASET = BASE / "phishguard_dataset_1000.csv"
RESULTS = BASE / "phishguard_results_1000.csv"
SUMMARY = BASE / "phishguard_results_summary.txt"


# ============================================================
# SAFE TLS ENGINE FOR BULK RESEARCH TEST
# ============================================================
# The 1,000-site research run does NOT connect to the phishing
# websites. TLS testing can be performed separately later.
# ============================================================

class OfflineTLSEngine:
    def analyze(self, host):
        return {
            "validated": False,
            "subject": "Not tested in safe bulk mode",
            "issuer": "Not tested in safe bulk mode",
            "days_left": None,
            "error": None,
            "score": 0,
            "tested": "TLS disabled during safe 1,000-site bulk test"
        }


# ============================================================
# RESEARCH SCORING CORRECTION
# ============================================================
# Brand and TLS EvidenceItems are already placed into evidence
# by PhishGuard. This prevents those indicators from being
# counted a second time during this research run.
#
# IMPORTANT:
# This changes the scoring calculation IN MEMORY ONLY for this
# research script. It does NOT rewrite phishguard_v22.py.
# ============================================================

def corrected_risk_calculation(self, evidence, brand, tls):
    risk = sum(item.score for item in evidence)

    # Preserve existing exact-official-domain trust credit.
    if brand.get("official"):
        risk -= 25

    return max(0, min(100, risk))


pg.RiskEngine.calculate = corrected_risk_calculation


def safe_div(a, b):
    return a / b if b else 0.0


def percent(value):
    return f"{value * 100:.2f}%"


def percentile(values, p):
    if not values:
        return 0.0

    values = sorted(values)
    index = int((len(values) - 1) * p)
    return values[index]


def load_dataset():

    if not DATASET.exists():
        raise SystemExit(
            "\nERROR: phishguard_dataset_1000.csv was not found.\n"
        )

    with DATASET.open(
        "r",
        newline="",
        encoding="utf-8"
    ) as f:
        rows = list(csv.DictReader(f))

    rows = [
        row for row in rows
        if row.get("url", "").strip()
    ]

    legitimate = sum(
        1 for row in rows
        if row.get("ground_truth", "").upper() == "LEGITIMATE"
    )

    phishing = sum(
        1 for row in rows
        if row.get("ground_truth", "").upper() == "PHISHING"
    )

    print()
    print("=" * 74)
    print("PHISHGUARD RESEARCH DATASET")
    print("=" * 74)
    print(f"Total observations:        {len(rows)}")
    print(f"Ground-truth legitimate:  {legitimate}")
    print(f"Ground-truth phishing:    {phishing}")
    print("=" * 74)
    print()

    if len(rows) != 1000:
        raise SystemExit(
            f"ERROR: Expected 1000 sites but found {len(rows)}."
        )

    if legitimate != 500 or phishing != 500:
        raise SystemExit(
            "ERROR: Expected 500 legitimate and 500 phishing sites."
        )

    return rows


def evidence_json(verdict):

    data = []

    for e in verdict.evidence:

        data.append({
            "category": e.category,
            "test_name": e.test_name,
            "score": e.score,
            "confidence": e.confidence,
            "status": e.status,
            "finding": e.finding,
            "why_it_matters": e.why_it_matters
        })

    return json.dumps(
        data,
        ensure_ascii=False
    )


def main():

    rows = load_dataset()

    engine = pg.PhishGuardEngine()

    # No network TLS connection during the bulk run.
    engine.tls_engine = OfflineTLSEngine()

    process = psutil.Process() if psutil else None

    if process:
        starting_memory = (
            process.memory_info().rss /
            1024 /
            1024
        )
        starting_cpu = sum(process.cpu_times()[:2])
    else:
        starting_memory = 0.0
        starting_cpu = 0.0

    start_all = time.perf_counter()

    results = []

    tp = 0
    tn = 0
    fp = 0
    fn = 0
    errors = 0

    allow_count = 0
    warn_count = 0
    block_count = 0

    latencies = []
    memory_samples = []

    print("Starting safe 1,000-site PhishGuard test...")
    print()
    print("Browser navigation:       OFF")
    print("Web page rendering:       OFF")
    print("TLS network connections:  OFF")
    print()
    print("WARN + BLOCK = phishing detection")
    print("ALLOW        = legitimate prediction")
    print()
    print("=" * 74)

    for index, row in enumerate(rows, start=1):

        url = row["url"].strip()
        truth = row.get(
            "ground_truth",
            ""
        ).strip().upper()

        start = time.perf_counter()

        try:
            verdict = engine.analyze(url)
            error_text = ""

        except Exception as exc:
            verdict = None
            error_text = (
                f"{type(exc).__name__}: {exc}"
            )

        latency_ms = (
            time.perf_counter() - start
        ) * 1000

        latencies.append(latency_ms)

        if process:
            memory_mb = (
                process.memory_info().rss /
                1024 /
                1024
            )
            memory_samples.append(memory_mb)
        else:
            memory_mb = 0.0

        sample_id = row.get(
            "sample_id",
            f"PG-{index:04d}"
        )

        if verdict is None:

            errors += 1

            results.append({
                "sample_id": sample_id,
                "url": url,
                "source": row.get("source", ""),
                "source_id": row.get("source_id", ""),
                "ground_truth": truth,
                "phishguard_decision": "ERROR",
                "risk_score": "",
                "binary_prediction": "ERROR",
                "classification": "ERROR",
                "likely_brand": "",
                "official_reference_domain": "",
                "brand_score": "",
                "analysis_latency_ms": round(latency_ms, 3),
                "memory_mb": round(memory_mb, 3),
                "evidence_count": 0,
                "evidence": "",
                "error": error_text
            })

            continue

        decision = verdict.decision

        if decision == "ALLOW":
            allow_count += 1
        elif decision == "WARN":
            warn_count += 1
        elif decision == "BLOCK":
            block_count += 1

        # For primary binary classification:
        # WARN and BLOCK both represent protective intervention.
        if decision in ("WARN", "BLOCK"):
            prediction = "PHISHING"
        else:
            prediction = "LEGITIMATE"

        if truth == "PHISHING" and prediction == "PHISHING":
            classification = "TP"
            tp += 1

        elif truth == "LEGITIMATE" and prediction == "LEGITIMATE":
            classification = "TN"
            tn += 1

        elif truth == "LEGITIMATE" and prediction == "PHISHING":
            classification = "FP"
            fp += 1

        elif truth == "PHISHING" and prediction == "LEGITIMATE":
            classification = "FN"
            fn += 1

        else:
            classification = "UNKNOWN"

        results.append({
            "sample_id": sample_id,
            "url": url,
            "source": row.get("source", ""),
            "source_id": row.get("source_id", ""),
            "ground_truth": truth,
            "phishguard_decision": decision,
            "risk_score": verdict.risk,
            "binary_prediction": prediction,
            "classification": classification,
            "likely_brand": verdict.brand.get(
                "brand",
                "unknown"
            ),
            "official_reference_domain": verdict.brand.get(
                "official_domain",
                "unknown"
            ),
            "brand_score": verdict.brand.get(
                "score",
                0
            ),
            "analysis_latency_ms": round(
                latency_ms,
                3
            ),
            "memory_mb": round(
                memory_mb,
                3
            ),
            "evidence_count": len(
                verdict.evidence
            ),
            "evidence": evidence_json(
                verdict
            ),
            "error": ""
        })

        if index == 1 or index % 25 == 0 or index == 1000:

            print(
                f"{index:4d}/1000 | "
                f"{truth:10s} -> "
                f"{decision:5s} | "
                f"Risk {verdict.risk:3d} | "
                f"{classification}"
            )

    total_time = (
        time.perf_counter() -
        start_all
    )

    if process:

        ending_cpu = sum(
            process.cpu_times()[:2]
        )

        cpu_seconds = (
            ending_cpu -
            starting_cpu
        )

        avg_cpu = (
            safe_div(
                cpu_seconds,
                total_time
            ) * 100
        )

        ending_memory = (
            process.memory_info().rss /
            1024 /
            1024
        )

    else:

        avg_cpu = 0.0
        ending_memory = 0.0

    evaluated = tp + tn + fp + fn

    accuracy = safe_div(
        tp + tn,
        evaluated
    )

    precision = safe_div(
        tp,
        tp + fp
    )

    recall = safe_div(
        tp,
        tp + fn
    )

    f1 = safe_div(
        2 * precision * recall,
        precision + recall
    )

    fpr = safe_div(
        fp,
        fp + tn
    )

    fnr = safe_div(
        fn,
        fn + tp
    )

    mean_latency = safe_div(
        sum(latencies),
        len(latencies)
    )

    median_latency = percentile(
        latencies,
        0.50
    )

    p95_latency = percentile(
        latencies,
        0.95
    )

    peak_memory = (
        max(memory_samples)
        if memory_samples
        else 0.0
    )

    fieldnames = [
        "sample_id",
        "url",
        "source",
        "source_id",
        "ground_truth",
        "phishguard_decision",
        "risk_score",
        "binary_prediction",
        "classification",
        "likely_brand",
        "official_reference_domain",
        "brand_score",
        "analysis_latency_ms",
        "memory_mb",
        "evidence_count",
        "evidence",
        "error"
    ]

    with RESULTS.open(
        "w",
        newline="",
        encoding="utf-8"
    ) as f:

        writer = csv.DictWriter(
            f,
            fieldnames=fieldnames
        )

        writer.writeheader()
        writer.writerows(results)

    summary = f"""
PHISHGUARD 1,000-SITE RESEARCH TEST
===================================

DATASET
-------
Total observations:       {len(rows)}
Legitimate:               500
Phishing:                 500
Processing errors:        {errors}

RAW PHISHGUARD DECISIONS
------------------------
ALLOW:                    {allow_count}
WARN:                     {warn_count}
BLOCK:                    {block_count}

PRIMARY BINARY ANALYSIS
-----------------------
WARN + BLOCK = PHISHING
ALLOW        = LEGITIMATE

CONFUSION MATRIX
----------------
True Positives (TP):      {tp}
True Negatives (TN):      {tn}
False Positives (FP):     {fp}
False Negatives (FN):     {fn}

CLASSIFICATION METRICS
----------------------
Accuracy:                 {percent(accuracy)}
Precision:                {percent(precision)}
Recall / Sensitivity:     {percent(recall)}
F1 Score:                 {percent(f1)}
False Positive Rate:      {percent(fpr)}
False Negative Rate:      {percent(fnr)}

PERFORMANCE
-----------
Total processing time:    {total_time:.3f} seconds
Mean analysis latency:    {mean_latency:.3f} ms
Median latency:           {median_latency:.3f} ms
95th percentile latency:  {p95_latency:.3f} ms

Starting memory:          {starting_memory:.3f} MB
Ending memory:            {ending_memory:.3f} MB
Peak memory:              {peak_memory:.3f} MB
Approx. process CPU:      {avg_cpu:.2f}%

EXPERIMENTAL MODE
-----------------
Browser navigation:       DISABLED
Web page rendering:       DISABLED
TLS network validation:   DISABLED

This test evaluates the local URL, domain structure, lexical,
brand-impersonation, typosquatting, internationalized-domain,
keyword, and weighted-risk components of PhishGuard.

TLS validation should be evaluated separately in a controlled
experimental environment before reporting final full-system
performance.
""".strip()

    SUMMARY.write_text(
        summary + "\n",
        encoding="utf-8"
    )

    print()
    print("=" * 74)
    print()
    print(summary)
    print()
    print("=" * 74)
    print()
    print("FILES CREATED:")
    print(RESULTS)
    print(SUMMARY)
    print()


if __name__ == "__main__":
    main()
