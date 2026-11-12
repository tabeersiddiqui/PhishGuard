"""
PhishGuard H4 Local-Analysis / Network-Dependency Experiment

Purpose:
Evaluate whether PhishGuard retains phishing-analysis functionality when
destination-dependent TLS inspection is unavailable, while determining how
much the resulting classifications depend on that network-dependent component.

Experimental conditions:

A_NETWORK_CAPABLE
    PhishGuard v2.3 local multi-indicator analysis with normal TLS inspection.

B_LOCAL_ONLY
    Same PhishGuard v2.3 architecture with destination-dependent TLS inspection
    intentionally unavailable. URL, domain, brand, lexical, structural, IDN,
    and other local indicators remain active.

Threat intelligence is OFF in both conditions.

IMPORTANT:
The local-only condition does not treat unavailable TLS as suspicious.
It returns a neutral TLS result with score 0. This prevents simulated lack
of network availability from artificially increasing phishing risk.

This experiment does not claim that PhishGuard performs every function
without network access. It measures classification continuity and changes
when destination-dependent TLS inspection is removed.
"""

import csv
import time
import statistics
from pathlib import Path

import psutil
import phishguard_v23 as v23


# ============================================================
# CONFIGURATION
# ============================================================

DATASET = "phishguard_dataset_validation.csv"

DETAIL_OUTPUT = "h4_local_analysis_results.csv"
SUMMARY_OUTPUT = "h4_local_analysis_summary.txt"

WARN_MIN = 45
BLOCK_MIN = 70


# ============================================================
# CONTROLLED LOCAL-ONLY TLS COMPONENT
# ============================================================

class LocalOnlyTLSEngine:
    """
    Controlled replacement for the normal destination-dependent TLS engine.

    The component performs no socket connection and returns a neutral TLS
    result. Lack of TLS availability is therefore recorded as unavailable
    rather than scored as evidence of phishing.
    """

    def analyze(self, host):
        return {
            "validated": False,
            "subject": "Not evaluated in local-only condition",
            "issuer": "Not evaluated in local-only condition",
            "days_left": None,
            "error": None,
            "score": 0,
            "tested": (
                "TLS inspection intentionally unavailable during "
                "controlled local-only H4 condition"
            ),
        }


# ============================================================
# HELPERS
# ============================================================

def read_dataset(path):
    rows = []

    with open(path, "r", newline="", encoding="utf-8-sig") as handle:
        reader = csv.DictReader(handle)

        for row in reader:
            url = (
                row.get("url")
                or row.get("URL")
                or row.get("website")
                or row.get("Website")
            )

            if not url:
                continue

            sample_id = (
                row.get("sample_id")
                or row.get("Sample_ID")
                or row.get("id")
                or ""
            )

            ground_truth = (
                row.get("ground_truth")
                or row.get("label")
                or row.get("classification")
                or ""
            )

            rows.append(
                {
                    "sample_id": sample_id,
                    "url": url.strip(),
                    "ground_truth": ground_truth.strip().upper(),
                }
            )

    return rows


def safe_net_io():
    try:
        counters = psutil.net_io_counters()

        return {
            "bytes_sent": counters.bytes_sent,
            "bytes_recv": counters.bytes_recv,
        }

    except Exception:
        return {
            "bytes_sent": 0,
            "bytes_recv": 0,
        }


def elapsed_ms(start, end):
    return (end - start) * 1000.0


def is_positive(decision):
    return decision in {"WARN", "BLOCK"}


def classification_metrics(rows, prefix):
    tp = tn = fp = fn = 0

    for row in rows:
        truth = row["ground_truth"]
        decision = row[f"{prefix}_decision"]

        predicted_phishing = is_positive(decision)

        if truth == "PHISHING":
            if predicted_phishing:
                tp += 1
            else:
                fn += 1

        elif truth == "LEGITIMATE":
            if predicted_phishing:
                fp += 1
            else:
                tn += 1

    total = tp + tn + fp + fn

    accuracy = (
        (tp + tn) / total
        if total
        else 0.0
    )

    precision = (
        tp / (tp + fp)
        if (tp + fp)
        else 0.0
    )

    recall = (
        tp / (tp + fn)
        if (tp + fn)
        else 0.0
    )

    f1 = (
        2 * precision * recall / (precision + recall)
        if (precision + recall)
        else 0.0
    )

    fpr = (
        fp / (fp + tn)
        if (fp + tn)
        else 0.0
    )

    fnr = (
        fn / (fn + tp)
        if (fn + tp)
        else 0.0
    )

    return {
        "TP": tp,
        "TN": tn,
        "FP": fp,
        "FN": fn,
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "fpr": fpr,
        "fnr": fnr,
    }


# ============================================================
# LOAD DATASET
# ============================================================

dataset_path = Path(DATASET)

if not dataset_path.exists():
    raise FileNotFoundError(
        f"Dataset not found: {DATASET}"
    )

rows = read_dataset(DATASET)

if not rows:
    raise RuntimeError(
        "No usable observations found."
    )


# ============================================================
# CREATE TWO CONTROLLED CONDITIONS
# ============================================================

network_engine = v23.EnhancedPhishGuardEngine()

local_engine = v23.EnhancedPhishGuardEngine()
local_engine.tls_engine = LocalOnlyTLSEngine()


# ============================================================
# HEADER
# ============================================================

print()
print("=" * 72)
print("PHISHGUARD H4 LOCAL-ANALYSIS / NETWORK-DEPENDENCY EXPERIMENT")
print("=" * 72)
print()
print(f"Dataset: {DATASET}")
print(f"Observations: {len(rows)}")
print()
print("Condition A: NETWORK-CAPABLE LOCAL ANALYSIS")
print("  Local PhishGuard indicators: ON")
print("  TLS destination inspection: ON")
print("  Threat intelligence: OFF")
print()
print("Condition B: LOCAL-ONLY ANALYSIS")
print("  Local PhishGuard indicators: ON")
print("  TLS destination inspection: OFF")
print("  Threat intelligence: OFF")
print()


# ============================================================
# NETWORK-CAPABLE CONDITION
# ============================================================

print("Running Condition A: network-capable analysis...")

network_before = safe_net_io()

condition_a = {}

for index, row in enumerate(rows, start=1):

    start = time.perf_counter()

    try:
        verdict = network_engine.analyze(row["url"])
        error = ""
    except Exception as exc:
        verdict = None
        error = str(exc)

    end = time.perf_counter()

    if verdict is not None:
        condition_a[index] = {
            "decision": verdict.decision,
            "risk": verdict.risk,
            "latency_ms": elapsed_ms(start, end),
            "error": error,
        }
    else:
        condition_a[index] = {
            "decision": "ERROR",
            "risk": "",
            "latency_ms": elapsed_ms(start, end),
            "error": error,
        }

    if index % 25 == 0 or index == len(rows):
        print(f"  Condition A: {index}/{len(rows)}")

network_after = safe_net_io()

a_bytes_sent = max(
    0,
    network_after["bytes_sent"]
    - network_before["bytes_sent"],
)

a_bytes_recv = max(
    0,
    network_after["bytes_recv"]
    - network_before["bytes_recv"],
)


# ============================================================
# LOCAL-ONLY CONDITION
# ============================================================

print()
print("Running Condition B: controlled local-only analysis...")

local_before = safe_net_io()

condition_b = {}

for index, row in enumerate(rows, start=1):

    start = time.perf_counter()

    try:
        verdict = local_engine.analyze(row["url"])
        error = ""
    except Exception as exc:
        verdict = None
        error = str(exc)

    end = time.perf_counter()

    if verdict is not None:
        condition_b[index] = {
            "decision": verdict.decision,
            "risk": verdict.risk,
            "latency_ms": elapsed_ms(start, end),
            "error": error,
        }
    else:
        condition_b[index] = {
            "decision": "ERROR",
            "risk": "",
            "latency_ms": elapsed_ms(start, end),
            "error": error,
        }

    if index % 25 == 0 or index == len(rows):
        print(f"  Condition B: {index}/{len(rows)}")

local_after = safe_net_io()

b_bytes_sent = max(
    0,
    local_after["bytes_sent"]
    - local_before["bytes_sent"],
)

b_bytes_recv = max(
    0,
    local_after["bytes_recv"]
    - local_before["bytes_recv"],
)


# ============================================================
# PAIRED RESULTS
# ============================================================

paired = []

for index, row in enumerate(rows, start=1):

    a = condition_a[index]
    b = condition_b[index]

    same_decision = (
        a["decision"] == b["decision"]
    )

    if (
        a["risk"] != ""
        and b["risk"] != ""
    ):
        risk_difference = (
            int(b["risk"]) - int(a["risk"])
        )
    else:
        risk_difference = ""

    paired.append(
        {
            "observation": index,
            "sample_id": row["sample_id"],
            "url": row["url"],
            "ground_truth": row["ground_truth"],

            "network_decision": a["decision"],
            "network_risk": a["risk"],
            "network_latency_ms": round(
                a["latency_ms"],
                3,
            ),
            "network_error": a["error"],

            "local_decision": b["decision"],
            "local_risk": b["risk"],
            "local_latency_ms": round(
                b["latency_ms"],
                3,
            ),
            "local_error": b["error"],

            "same_decision": same_decision,
            "risk_difference_local_minus_network": (
                risk_difference
            ),
        }
    )


# ============================================================
# WRITE DETAILED RESULTS
# ============================================================

fieldnames = [
    "observation",
    "sample_id",
    "url",
    "ground_truth",
    "network_decision",
    "network_risk",
    "network_latency_ms",
    "network_error",
    "local_decision",
    "local_risk",
    "local_latency_ms",
    "local_error",
    "same_decision",
    "risk_difference_local_minus_network",
]

with open(
    DETAIL_OUTPUT,
    "w",
    newline="",
    encoding="utf-8",
) as handle:

    writer = csv.DictWriter(
        handle,
        fieldnames=fieldnames,
    )

    writer.writeheader()
    writer.writerows(paired)


# ============================================================
# METRICS
# ============================================================

a_metrics = classification_metrics(
    paired,
    "network",
)

b_metrics = classification_metrics(
    paired,
    "local",
)


same_count = sum(
    1
    for row in paired
    if row["same_decision"]
)

different_count = (
    len(paired) - same_count
)

decision_agreement = (
    same_count / len(paired) * 100.0
)


network_latencies = [
    float(row["network_latency_ms"])
    for row in paired
    if not row["network_error"]
]

local_latencies = [
    float(row["local_latency_ms"])
    for row in paired
    if not row["local_error"]
]


network_mean_latency = (
    statistics.mean(network_latencies)
    if network_latencies
    else 0.0
)

network_median_latency = (
    statistics.median(network_latencies)
    if network_latencies
    else 0.0
)

local_mean_latency = (
    statistics.mean(local_latencies)
    if local_latencies
    else 0.0
)

local_median_latency = (
    statistics.median(local_latencies)
    if local_latencies
    else 0.0
)


network_errors = sum(
    1
    for row in paired
    if row["network_error"]
)

local_errors = sum(
    1
    for row in paired
    if row["local_error"]
)


changed_to_allow = sum(
    1
    for row in paired
    if (
        row["network_decision"] in {"WARN", "BLOCK"}
        and row["local_decision"] == "ALLOW"
    )
)

changed_to_warning = sum(
    1
    for row in paired
    if (
        row["network_decision"] == "ALLOW"
        and row["local_decision"] in {"WARN", "BLOCK"}
    )
)


# ============================================================
# SUMMARY
# ============================================================

summary = []

summary.append("=" * 72)
summary.append(
    "PHISHGUARD H4 LOCAL-ANALYSIS / NETWORK-DEPENDENCY EXPERIMENT"
)
summary.append("=" * 72)
summary.append("")

summary.append(f"Dataset: {DATASET}")
summary.append(f"Observations: {len(paired)}")
summary.append("Threat intelligence: OFF in both conditions")
summary.append("")

summary.append("CONDITION A - NETWORK-CAPABLE")
summary.append("-" * 72)
summary.append("Local multi-indicator analysis: ON")
summary.append("TLS destination inspection: ON")
summary.append(
    f"Errors: {network_errors}"
)
summary.append(
    f"TP: {a_metrics['TP']}"
)
summary.append(
    f"TN: {a_metrics['TN']}"
)
summary.append(
    f"FP: {a_metrics['FP']}"
)
summary.append(
    f"FN: {a_metrics['FN']}"
)
summary.append(
    f"Accuracy: {a_metrics['accuracy'] * 100:.2f}%"
)
summary.append(
    f"Precision: {a_metrics['precision'] * 100:.2f}%"
)
summary.append(
    f"Recall: {a_metrics['recall'] * 100:.2f}%"
)
summary.append(
    f"F1-score: {a_metrics['f1'] * 100:.2f}%"
)
summary.append(
    f"FPR: {a_metrics['fpr'] * 100:.2f}%"
)
summary.append(
    f"FNR: {a_metrics['fnr'] * 100:.2f}%"
)
summary.append(
    f"Mean latency: {network_mean_latency:.3f} ms"
)
summary.append(
    f"Median latency: {network_median_latency:.3f} ms"
)
summary.append(
    f"System bytes sent during condition: {a_bytes_sent}"
)
summary.append(
    f"System bytes received during condition: {a_bytes_recv}"
)
summary.append("")

summary.append("CONDITION B - CONTROLLED LOCAL-ONLY")
summary.append("-" * 72)
summary.append("Local multi-indicator analysis: ON")
summary.append("TLS destination inspection: OFF")
summary.append(
    f"Errors: {local_errors}"
)
summary.append(
    f"TP: {b_metrics['TP']}"
)
summary.append(
    f"TN: {b_metrics['TN']}"
)
summary.append(
    f"FP: {b_metrics['FP']}"
)
summary.append(
    f"FN: {b_metrics['FN']}"
)
summary.append(
    f"Accuracy: {b_metrics['accuracy'] * 100:.2f}%"
)
summary.append(
    f"Precision: {b_metrics['precision'] * 100:.2f}%"
)
summary.append(
    f"Recall: {b_metrics['recall'] * 100:.2f}%"
)
summary.append(
    f"F1-score: {b_metrics['f1'] * 100:.2f}%"
)
summary.append(
    f"FPR: {b_metrics['fpr'] * 100:.2f}%"
)
summary.append(
    f"FNR: {b_metrics['fnr'] * 100:.2f}%"
)
summary.append(
    f"Mean latency: {local_mean_latency:.3f} ms"
)
summary.append(
    f"Median latency: {local_median_latency:.3f} ms"
)
summary.append(
    f"System bytes sent during condition: {b_bytes_sent}"
)
summary.append(
    f"System bytes received during condition: {b_bytes_recv}"
)
summary.append("")

summary.append("PAIRED FUNCTIONAL CONTINUITY")
summary.append("-" * 72)
summary.append(
    f"Same ALLOW/WARN/BLOCK decision: "
    f"{same_count}/{len(paired)} "
    f"({decision_agreement:.2f}%)"
)
summary.append(
    f"Different decision: {different_count}/{len(paired)}"
)
summary.append(
    f"Network WARN/BLOCK -> Local ALLOW: {changed_to_allow}"
)
summary.append(
    f"Network ALLOW -> Local WARN/BLOCK: {changed_to_warning}"
)
summary.append("")

summary.append("DESCRIPTIVE NETWORK OBSERVATION")
summary.append("-" * 72)
summary.append(
    f"Condition A total observed system network bytes: "
    f"{a_bytes_sent + a_bytes_recv}"
)
summary.append(
    f"Condition B total observed system network bytes: "
    f"{b_bytes_sent + b_bytes_recv}"
)
summary.append("")
summary.append(
    "Network counters are system-wide interface counters and cannot be "
    "attributed exclusively to the PhishGuard process."
)
summary.append(
    "The controlled local-only TLS replacement itself performs no "
    "socket or destination-host connection."
)
summary.append("")

summary.append("INTERPRETATION BOUNDARY")
summary.append("-" * 72)
summary.append(
    "This experiment evaluates whether PhishGuard's local detection "
    "functions continue to produce classifications when destination-dependent "
    "TLS inspection is unavailable."
)
summary.append(
    "It does not establish that the complete application is fully offline, "
    "nor does it claim zero operating-system or unrelated network traffic."
)
summary.append(
    "Threat-intelligence matching is intentionally excluded from both "
    "conditions to isolate local analysis and TLS dependency."
)
summary.append("")

summary.append("=" * 72)
summary.append("H4 EXPERIMENT COMPLETE")
summary.append("=" * 72)
summary.append("")
summary.append(
    f"Detailed results: {DETAIL_OUTPUT}"
)
summary.append(
    f"Summary: {SUMMARY_OUTPUT}"
)

summary_text = "\n".join(summary)

with open(
    SUMMARY_OUTPUT,
    "w",
    encoding="utf-8",
) as handle:
    handle.write(summary_text)

print()
print(summary_text)

