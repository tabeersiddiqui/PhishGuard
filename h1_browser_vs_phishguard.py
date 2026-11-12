import csv
import math
import statistics
import sys
import time
from pathlib import Path

import phishguard_v241 as v241
import phishguard_v23 as v23


DATASET = "phishguard_dataset_final_untouched.csv"
BROWSER_RESULTS = "h1_browser_results.csv"
OUTPUT = "h1_paired_results.csv"
SUMMARY = "h1_summary.txt"


def normalize_label(value):
    value = (value or "").strip().upper()

    if value in {"PHISHING", "PHISH", "MALICIOUS", "1"}:
        return "PHISHING"

    if value in {"LEGITIMATE", "LEGIT", "BENIGN", "0"}:
        return "LEGITIMATE"

    return value


def phishguard_prediction(decision):
    if decision in {"WARN", "BLOCK"}:
        return "PHISHING"

    return "LEGITIMATE"


def safe_div(a, b):
    if b == 0:
        return 0.0

    return a / b


def browser_result(value):
    value = (value or "").strip().upper()

    if value in {"YES", "Y", "TRUE", "1"}:
        return "YES"

    if value in {"NO", "N", "FALSE", "0"}:
        return "NO"

    if value in {"NE", "N/E", "NOT EVALUABLE"}:
        return "NE"

    return ""


def mcnemar_exact(browser_only, phishguard_only):
    n = browser_only + phishguard_only

    if n == 0:
        return 1.0

    k = min(browser_only, phishguard_only)
    probability = 0.0

    for i in range(k + 1):
        probability += math.comb(n, i) * (0.5 ** n)

    return min(1.0, 2.0 * probability)


def load_dataset():
    path = Path(DATASET)

    if not path.exists():
        print()
        print("ERROR: Dataset was not found:")
        print(DATASET)
        print()
        print("Files in the current folder:")

        for item in Path(".").glob("*.csv"):
            print(" -", item.name)

        sys.exit(1)

    with path.open(
        "r",
        newline="",
        encoding="utf-8-sig"
    ) as file:
        rows = list(csv.DictReader(file))

    if not rows:
        print("ERROR: Dataset is empty.")
        sys.exit(1)

    return rows


def create_browser_template(dataset):
    path = Path(BROWSER_RESULTS)

    if path.exists():
        return False

    with path.open(
        "w",
        newline="",
        encoding="utf-8"
    ) as file:
        writer = csv.writer(file)

        writer.writerow([
            "sample_id",
            "url",
            "ground_truth",
            "browser_warning",
            "browser_blocked",
            "notes"
        ])

        for index, row in enumerate(dataset, 1):
            sample_id = row.get("sample_id")

            if not sample_id:
                sample_id = f"S{index:04d}"

            url = row.get("url", "")
            truth = normalize_label(row.get("ground_truth", ""))

            writer.writerow([
                sample_id,
                url,
                truth,
                "",
                "",
                ""
            ])

    return True


def load_browser_results():
    with open(
        BROWSER_RESULTS,
        "r",
        newline="",
        encoding="utf-8-sig"
    ) as file:
        return list(csv.DictReader(file))


def main():
    dataset = load_dataset()

    created = create_browser_template(dataset)

    if created:
        print()
        print("=" * 70)
        print("H1 BROWSER CONTROL WORKSHEET CREATED")
        print("=" * 70)
        print()
        print(f"Dataset observations: {len(dataset)}")
        print()
        print("Created:")
        print(BROWSER_RESULTS)
        print()
        print(
            "For each observation, enter YES or NO "
            "in the browser_warning column."
        )
        print()
        print(
            "Use YES only when the default browser "
            "produces a phishing/deceptive-site warning."
        )
        print()
        print(
            "Use NO when the browser does not produce "
            "that warning."
        )
        print()
        print(
            "Do not bypass browser warnings, enter credentials, "
            "or submit forms."
        )
        print()
        print(
            "After completing the worksheet, save it and "
            "run this script again."
        )
        print()
        return

    browser_rows = load_browser_results()
    browser_map = {}
    incomplete = []
    invalid = []

    for row in browser_rows:
        sample_id = (row.get("sample_id") or "").strip()
        warning = browser_result(
            row.get("browser_warning", "")
        )

        if sample_id:
            browser_map[sample_id] = row

        if not (row.get("browser_warning") or "").strip():
            incomplete.append(sample_id)

        elif not warning:
            invalid.append(sample_id)

    if incomplete:
        print()
        print("H1 browser worksheet is not complete.")
        print()
        print(
            f"Rows still requiring YES, NO, or NE: {len(incomplete)}"
        )
        print()
        print(
            "First incomplete samples:",
            ", ".join(incomplete[:10])
        )
        print()
        return

    if invalid:
        print()
        print("H1 browser worksheet contains invalid entries.")
        print()
        print(
            "Use only YES, NO, or NE in browser_warning."
        )
        print()
        print(
            "First invalid samples:",
            ", ".join(invalid[:10])
        )
        print()
        return

    print()
    print("=" * 70)
    print("H1: BROWSER VS. PHISHGUARD")
    print("=" * 70)
    print()

    # PRIMARY H1 CONFIGURATION:
    # Use PhishGuard's enhanced local multi-indicator engine.
    # TLS analysis remains enabled.
    # External PhishTank/OpenPhish threat-intelligence matching
    # is intentionally excluded from the primary H1 comparison
    # to prevent overlap with the phishing dataset source.
    engine = v23.EnhancedPhishGuardEngine()

    output_rows = []

    TP = 0
    TN = 0
    FP = 0
    FN = 0

    browser_tp = 0
    browser_fn = 0

    both_detected = 0
    browser_only = 0
    phishguard_only = 0
    neither_detected = 0
    not_evaluable = 0

    latencies = []

    for index, row in enumerate(dataset, 1):
        sample_id = row.get("sample_id")

        if not sample_id:
            sample_id = f"S{index:04d}"

        url = row.get("url", "")
        truth = normalize_label(row.get("ground_truth", ""))

        if sample_id not in browser_map:
            print()
            print(
                "ERROR: Missing browser result for sample:",
                sample_id
            )
            return

        browser_row = browser_map[sample_id]

        browser_status = browser_result(
            browser_row.get("browser_warning", "")
        )

        browser_evaluable = browser_status != "NE"
        browser_detected = browser_status == "YES"

        if not browser_evaluable:
            not_evaluable += 1

        start_time = time.perf_counter()

        verdict = engine.analyze(url)

        elapsed_ms = (
            time.perf_counter() - start_time
        ) * 1000.0

        latencies.append(elapsed_ms)

        pg_prediction = phishguard_prediction(
            verdict.decision
        )

        if truth == "PHISHING" and pg_prediction == "PHISHING":
            classification = "TP"
            TP += 1

        elif truth == "LEGITIMATE" and pg_prediction == "LEGITIMATE":
            classification = "TN"
            TN += 1

        elif truth == "LEGITIMATE" and pg_prediction == "PHISHING":
            classification = "FP"
            FP += 1

        else:
            classification = "FN"
            FN += 1

        if truth == "PHISHING" and browser_evaluable:
            pg_detected = pg_prediction == "PHISHING"

            if browser_detected:
                browser_tp += 1
            else:
                browser_fn += 1

            if browser_detected and pg_detected:
                both_detected += 1

            elif browser_detected and not pg_detected:
                browser_only += 1

            elif not browser_detected and pg_detected:
                phishguard_only += 1

            else:
                neither_detected += 1

        intel = getattr(
            verdict,
            "threat_intel",
            {}
        ) or {}

        output_rows.append({
            "sample_id": sample_id,
            "url": url,
            "ground_truth": truth,
            "browser_detected": browser_status,
            "browser_evaluable": (
                "YES" if browser_evaluable else "NO"
            ),
            "phishguard_decision": verdict.decision,
            "phishguard_risk": verdict.risk,
            "phishguard_prediction": pg_prediction,
            "classification": classification,
            "latency_ms": round(elapsed_ms, 3),
            "threat_intel_match": intel.get(
                "matched",
                False
            ),
            "threat_intel_match_type": intel.get(
                "match_type",
                ""
            ),
            "local_risk": intel.get(
                "local_risk",
                ""
            )
        })

        if index % 25 == 0:
            print(
                f"Processed {index}/{len(dataset)}"
            )

    with open(
        OUTPUT,
        "w",
        newline="",
        encoding="utf-8"
    ) as file:
        writer = csv.DictWriter(
            file,
            fieldnames=list(output_rows[0].keys())
        )

        writer.writeheader()
        writer.writerows(output_rows)

    accuracy = safe_div(
        TP + TN,
        TP + TN + FP + FN
    )

    precision = safe_div(
        TP,
        TP + FP
    )

    recall = safe_div(
        TP,
        TP + FN
    )

    f1 = safe_div(
        2 * precision * recall,
        precision + recall
    )

    fpr = safe_div(
        FP,
        FP + TN
    )

    fnr = safe_div(
        FN,
        FN + TP
    )

    p_value = mcnemar_exact(
        browser_only,
        phishguard_only
    )

    mean_latency = statistics.mean(latencies)
    median_latency = statistics.median(latencies)

    summary = f"""
PHISHGUARD H1 COMPLEMENTARY DETECTION TEST
==========================================

Total observations: {len(dataset)}
Browser not-evaluable observations: {not_evaluable}
Browser evaluable observations: {len(dataset) - not_evaluable}

PHISHGUARD CONFUSION MATRIX
TP: {TP}
TN: {TN}
FP: {FP}
FN: {FN}

PHISHGUARD PERFORMANCE
Accuracy:  {accuracy * 100:.2f}%
Precision: {precision * 100:.2f}%
Recall:    {recall * 100:.2f}%
F1-score:  {f1 * 100:.2f}%
FPR:       {fpr * 100:.2f}%
FNR:       {fnr * 100:.2f}%

PAIRED PHISHING DETECTION
Detected by both:       {both_detected}
Browser only:           {browser_only}
PhishGuard only:        {phishguard_only}
Detected by neither:    {neither_detected}
Not evaluable:            {not_evaluable}

Browser phishing detections: {browser_tp}
Browser phishing misses:     {browser_fn}

STATISTICAL COMPARISON
Exact McNemar p-value: {p_value:.6f}
Alpha: .05

PHISHGUARD ANALYSIS LATENCY
Mean:   {mean_latency:.3f} ms
Median: {median_latency:.3f} ms

INTERPRETATION NOTE
PhishGuard-only detections represent phishing observations
for which PhishGuard produced WARN or BLOCK while the default
browser did not produce a phishing/deceptive-site warning.

Statistical significance is evaluated at alpha = .05.
"""

    Path(SUMMARY).write_text(
        summary,
        encoding="utf-8"
    )

    print(summary)

    print()
    print(f"Detailed results: {OUTPUT}")
    print(f"Summary: {SUMMARY}")
    print()


if __name__ == "__main__":
    main()
