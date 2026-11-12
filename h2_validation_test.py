import csv
import time
from collections import Counter

import phishguard_v23 as v23


DATASET = "phishguard_dataset_validation.csv"
DETAIL_OUTPUT = "h2_validation_results.csv"
SUMMARY_OUTPUT = "h2_validation_summary.txt"

WARN_MIN = 45
BLOCK_MIN = 70


# ------------------------------------------------------------
# H2 EXPERIMENTAL CONFIGURATIONS
# ------------------------------------------------------------
#
# A = URL/domain-structure analysis only
# B = Brand/lexical analysis only
# C = TLS certificate analysis only
# D = Full multi-indicator PhishGuard
#
# Threat-intelligence matching is intentionally excluded.
# The experiment uses the local v2.3 multi-indicator engine.
#
# Evidence is generated once by the existing PhishGuard engine
# and then separated into experimental indicator families.
# ------------------------------------------------------------

CONFIGURATIONS = {
    "A_URL_DOMAIN": {
        "URL Structure",
        "Domain Structure",
        "Top-Level Domain",
        "Transport Security",
        "International Domain",
        "Typosquatting",
    },

    "B_BRAND_LEXICAL": {
        "Brand Impersonation",
        "Lexical Analysis",
        "Phishing Language",
    },

    "C_TLS": {
        "TLS Certificate",
    },

    "D_FULL": None,
}


def normalize_truth(value):
    value = str(value).strip().upper()

    if value in {"PHISHING", "PHISH", "MALICIOUS", "1"}:
        return "PHISHING"

    if value in {"LEGITIMATE", "LEGIT", "BENIGN", "0"}:
        return "LEGITIMATE"

    raise ValueError(f"Unknown ground-truth label: {value}")


def decision_from_risk(risk):
    if risk >= BLOCK_MIN:
        return "BLOCK"
    elif risk >= WARN_MIN:
        return "WARN"
    return "ALLOW"


def prediction_from_decision(decision):
    # Primary binary H2 analysis:
    # WARN and BLOCK are treated as positive phishing detections.
    return "PHISHING" if decision in {"WARN", "BLOCK"} else "LEGITIMATE"


def calculate_metrics(tp, tn, fp, fn):
    total = tp + tn + fp + fn

    accuracy = (tp + tn) / total if total else 0
    precision = tp / (tp + fp) if (tp + fp) else 0
    recall = tp / (tp + fn) if (tp + fn) else 0
    f1 = (
        2 * precision * recall / (precision + recall)
        if (precision + recall)
        else 0
    )
    fpr = fp / (fp + tn) if (fp + tn) else 0
    fnr = fn / (fn + tp) if (fn + tp) else 0

    return {
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "fpr": fpr,
        "fnr": fnr,
    }


def evidence_score(evidence, allowed_categories):
    if allowed_categories is None:
        selected = list(evidence)
    else:
        selected = [
            item
            for item in evidence
            if item.category in allowed_categories
        ]

    risk = sum(
        item.score
        for item in selected
        if item.score > 0
    )

    return max(0, min(100, int(round(risk)))), selected


def official_brand_credit(verdict, config_name, risk):
    """
    Preserve the existing v2.3 exact-official-brand trust credit
    only in configurations that contain brand analysis.

    The full v2.3 engine subtracts 25 points for an exact official
    brand/domain match. That behavior belongs to the brand subsystem.
    """

    if config_name not in {"B_BRAND_LEXICAL", "D_FULL"}:
        return risk

    try:
        if verdict.brand.get("official"):
            risk -= 25
    except Exception:
        pass

    return max(0, min(100, int(round(risk))))


with open(DATASET, newline="", encoding="utf-8-sig") as f:
    rows = list(csv.DictReader(f))


if not rows:
    raise RuntimeError("Development dataset is empty.")


print("=" * 72)
print("PHISHGUARD H2 MULTI-INDICATOR / SINGLE-INDICATOR EXPERIMENT")
print("=" * 72)
print(f"Dataset: {DATASET}")
print(f"Observations: {len(rows)}")
print("Threat intelligence: OFF")
print("TLS: ON")
print("WARN threshold: 45")
print("BLOCK threshold: 70")
print()


# Identify dataset column names.
fieldnames_lower = {
    name.lower(): name
    for name in rows[0].keys()
}

url_column = fieldnames_lower.get("url")

truth_column = (
    fieldnames_lower.get("ground_truth")
    or fieldnames_lower.get("label")
    or fieldnames_lower.get("classification")
)

sample_column = (
    fieldnames_lower.get("sample_id")
    or fieldnames_lower.get("id")
)


if not url_column:
    raise RuntimeError(
        "Could not identify the URL column in the dataset."
    )

if not truth_column:
    raise RuntimeError(
        "Could not identify the ground-truth column in the dataset."
    )


engine = v23.EnhancedPhishGuardEngine()

results = []
confusions = {
    name: Counter()
    for name in CONFIGURATIONS
}

decision_counts = {
    name: Counter()
    for name in CONFIGURATIONS
}

latencies = []

errors = 0


for index, row in enumerate(rows, start=1):

    sample_id = (
        row.get(sample_column, "")
        if sample_column
        else f"DEV-{index:04d}"
    )

    url = row[url_column].strip()
    truth = normalize_truth(row[truth_column])

    try:
        start = time.perf_counter()
        verdict = engine.analyze(url)
        elapsed_ms = (
            time.perf_counter() - start
        ) * 1000

        latencies.append(elapsed_ms)

        output_row = {
            "sample_id": sample_id,
            "url": url,
            "ground_truth": truth,
            "analysis_latency_ms": f"{elapsed_ms:.3f}",
        }

        for config_name, allowed_categories in CONFIGURATIONS.items():

            risk, selected = evidence_score(
                verdict.evidence,
                allowed_categories
            )

            risk = official_brand_credit(
                verdict,
                config_name,
                risk
            )

            decision = decision_from_risk(risk)
            prediction = prediction_from_decision(decision)

            decision_counts[config_name][decision] += 1

            if truth == "PHISHING" and prediction == "PHISHING":
                outcome = "TP"
            elif truth == "LEGITIMATE" and prediction == "LEGITIMATE":
                outcome = "TN"
            elif truth == "LEGITIMATE" and prediction == "PHISHING":
                outcome = "FP"
            else:
                outcome = "FN"

            confusions[config_name][outcome] += 1

            categories = sorted({
                item.category
                for item in selected
                if item.score > 0
            })

            tests = sorted({
                item.test_name
                for item in selected
                if item.score > 0
            })

            output_row[f"{config_name}_risk"] = risk
            output_row[f"{config_name}_decision"] = decision
            output_row[f"{config_name}_prediction"] = prediction
            output_row[f"{config_name}_outcome"] = outcome
            output_row[f"{config_name}_categories"] = "; ".join(categories)
            output_row[f"{config_name}_tests"] = "; ".join(tests)

        results.append(output_row)

    except Exception as exc:
        errors += 1
        print(
            f"ERROR {sample_id}: "
            f"{type(exc).__name__}: {exc}"
        )

    if index % 50 == 0 or index == len(rows):
        print(
            f"Processed {index}/{len(rows)}"
        )


if not results:
    raise RuntimeError(
        "No observations were successfully analyzed."
    )


# ------------------------------------------------------------
# SAVE DETAILED RESULTS
# ------------------------------------------------------------

output_fields = list(results[0].keys())

with open(
    DETAIL_OUTPUT,
    "w",
    newline="",
    encoding="utf-8"
) as f:

    writer = csv.DictWriter(
        f,
        fieldnames=output_fields
    )

    writer.writeheader()
    writer.writerows(results)


# ------------------------------------------------------------
# GENERATE SUMMARY
# ------------------------------------------------------------

summary = []

summary.append("=" * 72)
summary.append("PHISHGUARD H2 VALIDATION EXPERIMENT")
summary.append("=" * 72)
summary.append("")
summary.append(f"Dataset: {DATASET}")
summary.append(f"Successful observations: {len(results)}")
summary.append(f"Errors: {errors}")
summary.append("")
summary.append("Primary binary rule: WARN/BLOCK = phishing detection")
summary.append("ALLOW = legitimate prediction")
summary.append("Threat-intelligence matching: OFF")
summary.append("TLS analysis: ON")
summary.append("WARN threshold: 45")
summary.append("BLOCK threshold: 70")
summary.append("")


metrics_by_config = {}


for config_name in CONFIGURATIONS:

    c = confusions[config_name]

    tp = c["TP"]
    tn = c["TN"]
    fp = c["FP"]
    fn = c["FN"]

    metrics = calculate_metrics(
        tp, tn, fp, fn
    )

    metrics_by_config[config_name] = metrics

    summary.append("=" * 72)
    summary.append(config_name)
    summary.append("=" * 72)

    summary.append(f"TP: {tp}")
    summary.append(f"TN: {tn}")
    summary.append(f"FP: {fp}")
    summary.append(f"FN: {fn}")
    summary.append("")

    summary.append(
        f"Accuracy:  {metrics['accuracy'] * 100:.2f}%"
    )
    summary.append(
        f"Precision: {metrics['precision'] * 100:.2f}%"
    )
    summary.append(
        f"Recall:    {metrics['recall'] * 100:.2f}%"
    )
    summary.append(
        f"F1-score:  {metrics['f1'] * 100:.2f}%"
    )
    summary.append(
        f"FPR:       {metrics['fpr'] * 100:.2f}%"
    )
    summary.append(
        f"FNR:       {metrics['fnr'] * 100:.2f}%"
    )

    summary.append("")
    summary.append(
        "Decisions: "
        + str(dict(decision_counts[config_name]))
    )
    summary.append("")


# ------------------------------------------------------------
# DIRECT H2 COMPARISON
# ------------------------------------------------------------

summary.append("=" * 72)
summary.append("H2 ACCURACY COMPARISON")
summary.append("=" * 72)
summary.append("")

for config_name in CONFIGURATIONS:
    summary.append(
        f"{config_name}: "
        f"{metrics_by_config[config_name]['accuracy'] * 100:.2f}%"
    )


full_accuracy = metrics_by_config["D_FULL"]["accuracy"]

summary.append("")
summary.append("FULL MODEL ACCURACY DIFFERENCE:")

for config_name in [
    "A_URL_DOMAIN",
    "B_BRAND_LEXICAL",
    "C_TLS"
]:
    difference = (
        full_accuracy
        - metrics_by_config[config_name]["accuracy"]
    ) * 100

    summary.append(
        f"D_FULL minus {config_name}: "
        f"{difference:+.2f} percentage points"
    )


# ------------------------------------------------------------
# CONFIGURATION AGREEMENT
# ------------------------------------------------------------

summary.append("")
summary.append("=" * 72)
summary.append("CLASSIFICATION CONSISTENCY")
summary.append("=" * 72)
summary.append("")

for config_name in [
    "A_URL_DOMAIN",
    "B_BRAND_LEXICAL",
    "C_TLS"
]:

    same = 0
    different = 0

    for r in results:

        if (
            r[f"{config_name}_prediction"]
            ==
            r["D_FULL_prediction"]
        ):
            same += 1
        else:
            different += 1

    agreement = (
        same / len(results) * 100
        if results
        else 0
    )

    summary.append(
        f"{config_name} vs D_FULL:"
    )
    summary.append(
        f"  Same classification: {same}"
    )
    summary.append(
        f"  Different classification: {different}"
    )
    summary.append(
        f"  Agreement: {agreement:.2f}%"
    )
    summary.append("")


if latencies:
    sorted_latency = sorted(latencies)

    mean_latency = (
        sum(latencies) / len(latencies)
    )

    median_latency = sorted_latency[
        len(sorted_latency) // 2
    ]

    p95_index = min(
        len(sorted_latency) - 1,
        int(len(sorted_latency) * 0.95)
    )

    p95_latency = sorted_latency[p95_index]

    summary.append("=" * 72)
    summary.append("FULL ENGINE ANALYSIS LATENCY")
    summary.append("=" * 72)
    summary.append(
        f"Mean:   {mean_latency:.3f} ms"
    )
    summary.append(
        f"Median: {median_latency:.3f} ms"
    )
    summary.append(
        f"P95:    {p95_latency:.3f} ms"
    )
    summary.append("")


summary.append("=" * 72)
summary.append("IMPORTANT INTERPRETATION NOTE")
summary.append("=" * 72)
summary.append(
    "This development experiment compares indicator families within "
    "the existing frozen PhishGuard scoring architecture. It does not "
    "modify the underlying PhishGuard source code or decision thresholds."
)
summary.append(
    "Results should be interpreted as component/ablation evidence and "
    "not as an independent final validation result."
)


summary_text = "\n".join(summary)

with open(
    SUMMARY_OUTPUT,
    "w",
    encoding="utf-8"
) as f:
    f.write(summary_text)


print()
print(summary_text)

print()
print("=" * 72)
print("H2 DEVELOPMENT TEST COMPLETE")
print("=" * 72)
print(f"Detailed results: {DETAIL_OUTPUT}")
print(f"Summary: {SUMMARY_OUTPUT}")
