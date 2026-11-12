#!/usr/bin/env python3

import argparse
import csv
import json
import time
from pathlib import Path

import psutil

import phishguard_v22 as base
import phishguard_v23 as v23


BASE = Path(__file__).resolve().parent


DATASETS = {
    "development":
        BASE / "phishguard_dataset_development.csv",

    "validation":
        BASE / "phishguard_dataset_validation.csv",

    "final":
        BASE / "phishguard_dataset_final_untouched.csv"
}


class OfflineTLSEngine:
    """
    Safe bulk-testing TLS replacement.

    Prevents the research harness from establishing network
    connections to known phishing destinations.
    """

    def analyze(self, host):

        return {
            "validated": False,
            "subject": "Not tested in safe bulk mode",
            "issuer": "Not tested in safe bulk mode",
            "days_left": None,
            "error": None,
            "score": 0,
            "tested":
                "TLS disabled during safe bulk research test"
        }


def safe_div(a, b):
    return a / b if b else 0.0


def pct(value):
    return f"{value * 100:.2f}%"


def percentile(values, fraction):

    if not values:
        return 0.0

    values = sorted(values)

    index = int(
        (len(values) - 1)
        * fraction
    )

    return values[index]


def evidence_json(verdict):

    output = []

    for e in verdict.evidence:

        output.append({
            "category": e.category,
            "test_name": e.test_name,
            "score": e.score,
            "confidence": e.confidence,
            "status": e.status,
            "finding": e.finding,
            "why_it_matters": e.why_it_matters
        })

    return json.dumps(
        output,
        ensure_ascii=False
    )


def main():

    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--split",
        choices=[
            "development",
            "validation",
            "final"
        ],
        default="development"
    )

    parser.add_argument(
        "--confirm-freeze",
        action="store_true",
        help=(
            "Required to run the untouched final dataset."
        )
    )

    args = parser.parse_args()

    if (
        args.split == "final"
        and not args.confirm_freeze
    ):
        raise SystemExit(
            "\nFINAL DATASET LOCKED.\n\n"
            "Do not run the final dataset while tuning.\n"
            "After the code, features, weights, and thresholds "
            "are frozen, run:\n\n"
            "python research_test_v23.py "
            "--split final --confirm-freeze\n"
        )

    dataset = DATASETS[
        args.split
    ]

    if not dataset.exists():
        raise SystemExit(
            f"Dataset not found: {dataset}\n"
            "Run: python split_research_dataset.py"
        )

    with dataset.open(
        "r",
        newline="",
        encoding="utf-8"
    ) as f:

        rows = list(
            csv.DictReader(f)
        )

    print()
    print("=" * 74)
    print(
        f"PHISHGUARD V2.3 "
        f"{args.split.upper()} TEST"
    )
    print("=" * 74)
    print(
        f"Observations: {len(rows)}"
    )
    print(
        "Browser navigation: OFF"
    )
    print(
        "Web rendering:      OFF"
    )
    print(
        "TLS networking:     OFF"
    )
    print("=" * 74)
    print()

    # Ensure the underlying original engine uses offline TLS.
    base.TLSEngine = OfflineTLSEngine

    engine = v23.EnhancedPhishGuardEngine()

    engine.tls_engine = (
        OfflineTLSEngine()
    )

    process = psutil.Process()

    results = []

    tp = tn = fp = fn = 0
    allow = warn = block = errors = 0

    latencies = []
    memory_samples = []

    start_all = time.perf_counter()

    for i, row in enumerate(
        rows,
        start=1
    ):

        url = row["url"].strip()

        truth = (
            row["ground_truth"]
            .strip()
            .upper()
        )

        start = time.perf_counter()

        try:
            verdict = engine.analyze(url)
            error = ""

        except Exception as exc:
            verdict = None
            error = (
                f"{type(exc).__name__}: {exc}"
            )

        latency = (
            time.perf_counter()
            - start
        ) * 1000

        latencies.append(
            latency
        )

        memory = (
            process.memory_info().rss
            / 1024
            / 1024
        )

        memory_samples.append(
            memory
        )

        if verdict is None:

            errors += 1

            results.append({
                "sample_id":
                    row.get("sample_id", ""),
                "url": url,
                "ground_truth": truth,
                "decision": "ERROR",
                "risk_score": "",
                "prediction": "ERROR",
                "classification": "ERROR",
                "latency_ms":
                    round(latency, 3),
                "memory_mb":
                    round(memory, 3),
                "evidence": "",
                "error": error
            })

            continue

        decision = verdict.decision

        if decision == "ALLOW":
            allow += 1
            prediction = "LEGITIMATE"

        elif decision == "WARN":
            warn += 1
            prediction = "PHISHING"

        else:
            block += 1
            prediction = "PHISHING"

        if (
            truth == "PHISHING"
            and prediction == "PHISHING"
        ):
            classification = "TP"
            tp += 1

        elif (
            truth == "LEGITIMATE"
            and prediction == "LEGITIMATE"
        ):
            classification = "TN"
            tn += 1

        elif (
            truth == "LEGITIMATE"
            and prediction == "PHISHING"
        ):
            classification = "FP"
            fp += 1

        elif (
            truth == "PHISHING"
            and prediction == "LEGITIMATE"
        ):
            classification = "FN"
            fn += 1

        else:
            classification = "UNKNOWN"

        results.append({
            "sample_id":
                row.get("sample_id", ""),
            "url": url,
            "ground_truth": truth,
            "decision": decision,
            "risk_score": verdict.risk,
            "prediction": prediction,
            "classification":
                classification,
            "latency_ms":
                round(latency, 3),
            "memory_mb":
                round(memory, 3),
            "evidence":
                evidence_json(verdict),
            "error": ""
        })

        if (
            i == 1
            or i % 25 == 0
            or i == len(rows)
        ):

            print(
                f"{i:4d}/{len(rows)} | "
                f"{truth:10s} -> "
                f"{decision:5s} | "
                f"Risk {verdict.risk:3d} | "
                f"{classification}"
            )

    elapsed = (
        time.perf_counter()
        - start_all
    )

    evaluated = (
        tp + tn + fp + fn
    )

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

    peak_memory = max(
        memory_samples
    ) if memory_samples else 0.0

    result_path = (
        BASE /
        f"phishguard_v23_{args.split}_results.csv"
    )

    summary_path = (
        BASE /
        f"phishguard_v23_{args.split}_summary.txt"
    )

    fields = [
        "sample_id",
        "url",
        "ground_truth",
        "decision",
        "risk_score",
        "prediction",
        "classification",
        "latency_ms",
        "memory_mb",
        "evidence",
        "error"
    ]

    with result_path.open(
        "w",
        newline="",
        encoding="utf-8"
    ) as f:

        writer = csv.DictWriter(
            f,
            fieldnames=fields
        )

        writer.writeheader()
        writer.writerows(
            results
        )

    summary = f"""
PHISHGUARD V2.3 {args.split.upper()} TEST
{'=' * 48}

Observations:              {len(rows)}
Processing errors:         {errors}

RAW DECISIONS
-------------
ALLOW:                     {allow}
WARN:                      {warn}
BLOCK:                     {block}

CONFUSION MATRIX
----------------
True Positives (TP):       {tp}
True Negatives (TN):       {tn}
False Positives (FP):      {fp}
False Negatives (FN):      {fn}

METRICS
-------
Accuracy:                  {pct(accuracy)}
Precision:                 {pct(precision)}
Recall / Sensitivity:      {pct(recall)}
F1 Score:                  {pct(f1)}
False Positive Rate:       {pct(fpr)}
False Negative Rate:       {pct(fnr)}

LOCAL PERFORMANCE
-----------------
Total processing time:     {elapsed:.3f} seconds
Mean analysis latency:     {mean_latency:.3f} ms
Median latency:            {median_latency:.3f} ms
95th percentile latency:   {p95_latency:.3f} ms
Peak process memory:       {peak_memory:.3f} MB

EXPERIMENTAL MODE
-----------------
Browser navigation:        DISABLED
Web rendering:             DISABLED
TLS network validation:    DISABLED

WARN + BLOCK are treated as phishing detections for
the primary binary classification analysis.
""".strip()

    summary_path.write_text(
        summary + "\n",
        encoding="utf-8"
    )

    print()
    print(summary)
    print()
    print("FILES CREATED:")
    print(result_path)
    print(summary_path)
    print()


if __name__ == "__main__":
    main()
