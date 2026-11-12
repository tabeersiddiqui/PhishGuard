"""
PhishGuard H3 Operational Performance Experiment

Purpose:
Evaluate whether the locally deployed PhishGuard detection application
maintains acceptable operational performance during repeated real-time
phishing analyses.

H3 engineering thresholds:
    CPU utilization < 15%
    Memory utilization < 300 MB
    Analysis latency < 2.0 seconds

Configuration:
    PhishGuard v2.3 EnhancedPhishGuardEngine
    Threat intelligence OFF
    TLS ON
    Existing detector weights and thresholds unchanged

Important:
This is an operational performance experiment, not an accuracy experiment.
The script does not navigate to or render the tested websites.
"""

import csv
import os
import time
import statistics
from pathlib import Path

import psutil
import phishguard_v23 as v23


# ============================================================
# EXPERIMENT CONFIGURATION
# ============================================================

DATASET = "phishguard_dataset_validation.csv"

DETAIL_OUTPUT = "h3_performance_results.csv"
SUMMARY_OUTPUT = "h3_performance_summary.txt"

CPU_THRESHOLD = 15.0
MEMORY_THRESHOLD_MB = 300.0
LATENCY_THRESHOLD_MS = 2000.0

# Controlled pause between observations prevents the experiment
# from becoming a continuous tight-loop stress benchmark.
INTER_OBSERVATION_DELAY = 0.50

# Initial observations are used to warm the Python process,
# imported modules, and detector before formal measurements.
WARMUP_COUNT = 5


# ============================================================
# HELPER FUNCTIONS
# ============================================================

def percentile(values, percentile_value):
    if not values:
        return 0.0

    ordered = sorted(values)

    if len(ordered) == 1:
        return ordered[0]

    position = (len(ordered) - 1) * (percentile_value / 100.0)
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)

    if lower == upper:
        return ordered[lower]

    fraction = position - lower

    return (
        ordered[lower]
        + (ordered[upper] - ordered[lower]) * fraction
    )


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
                    "ground_truth": ground_truth,
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
        "No usable URL observations were found in the dataset."
    )


# ============================================================
# INITIALIZE ENGINE AND PROCESS MONITOR
# ============================================================

engine = v23.EnhancedPhishGuardEngine()

process = psutil.Process(os.getpid())

# Prime psutil's CPU measurement.
process.cpu_percent(interval=None)

logical_cpus = psutil.cpu_count(logical=True) or 1


# ============================================================
# EXPERIMENT HEADER
# ============================================================

print()
print("=" * 72)
print("PHISHGUARD H3 OPERATIONAL PERFORMANCE EXPERIMENT")
print("=" * 72)
print()
print(f"Dataset: {DATASET}")
print(f"Observations: {len(rows)}")
print("Engine: PhishGuard v2.3 EnhancedPhishGuardEngine")
print("Threat intelligence: OFF")
print("TLS: ON")
print()
print("Engineering acceptance thresholds:")
print(f"  CPU utilization: < {CPU_THRESHOLD:.0f}%")
print(f"  Memory utilization: < {MEMORY_THRESHOLD_MB:.0f} MB")
print(f"  Analysis latency: < {LATENCY_THRESHOLD_MS / 1000:.1f} seconds")
print()
print(f"Warm-up observations: {min(WARMUP_COUNT, len(rows))}")
print(
    f"Controlled delay between measured observations: "
    f"{INTER_OBSERVATION_DELAY:.2f} seconds"
)
print()


# ============================================================
# WARM-UP
# ============================================================

print("Beginning warm-up...")

warmup_rows = rows[:min(WARMUP_COUNT, len(rows))]

for index, row in enumerate(warmup_rows, start=1):
    try:
        engine.analyze(row["url"])
        print(f"Warm-up {index}/{len(warmup_rows)} complete")
    except Exception as exc:
        print(
            f"Warm-up {index}/{len(warmup_rows)} "
            f"encountered error: {exc}"
        )

    time.sleep(0.25)

print("Warm-up complete.")
print()


# Reset CPU measurement following warm-up.
process.cpu_percent(interval=None)

time.sleep(1.0)


# ============================================================
# BASELINE MEASUREMENTS
# ============================================================

baseline_memory_mb = (
    process.memory_info().rss / (1024 * 1024)
)

network_start = safe_net_io()

experiment_start = time.perf_counter()

results = []
errors = []


# ============================================================
# FORMAL MEASURED WORKLOAD
# ============================================================

print("Beginning formal H3 measurements...")
print()

for index, row in enumerate(rows, start=1):

    url = row["url"]

    memory_before_mb = (
        process.memory_info().rss / (1024 * 1024)
    )

    # Reset process CPU counter immediately before analysis.
    process.cpu_percent(interval=None)

    start_wall = time.perf_counter()
    start_cpu = time.process_time()

    verdict = None
    error_text = ""

    try:
        verdict = engine.analyze(url)

    except Exception as exc:
        error_text = str(exc)

    end_cpu = time.process_time()
    end_wall = time.perf_counter()

    latency_ms = (
        (end_wall - start_wall) * 1000.0
    )

    cpu_time_seconds = max(
        0.0,
        end_cpu - start_cpu,
    )

    wall_seconds = max(
        end_wall - start_wall,
        0.000001,
    )

    # CPU demand during the analysis interval.
    # Dividing by logical CPU count expresses consumption as a
    # percentage of total endpoint CPU capacity.
    cpu_percent = (
        (cpu_time_seconds / wall_seconds)
        * 100.0
        / logical_cpus
    )

    memory_after_mb = (
        process.memory_info().rss / (1024 * 1024)
    )

    memory_peak_observed_mb = max(
        memory_before_mb,
        memory_after_mb,
    )

    if verdict is not None:
        decision = getattr(verdict, "decision", "")
        risk = getattr(verdict, "risk", "")
    else:
        decision = "ERROR"
        risk = ""

    latency_pass = (
        latency_ms < LATENCY_THRESHOLD_MS
    )

    cpu_pass = (
        cpu_percent < CPU_THRESHOLD
    )

    memory_pass = (
        memory_peak_observed_mb < MEMORY_THRESHOLD_MB
    )

    result = {
        "observation": index,
        "sample_id": row["sample_id"],
        "url": url,
        "ground_truth": row["ground_truth"],
        "decision": decision,
        "risk": risk,
        "latency_ms": round(latency_ms, 3),
        "cpu_percent_total_capacity": round(cpu_percent, 3),
        "memory_before_mb": round(memory_before_mb, 3),
        "memory_after_mb": round(memory_after_mb, 3),
        "memory_peak_observed_mb": round(
            memory_peak_observed_mb,
            3,
        ),
        "latency_under_2_seconds": latency_pass,
        "cpu_under_15_percent": cpu_pass,
        "memory_under_300_mb": memory_pass,
        "error": error_text,
    }

    results.append(result)

    if error_text:
        errors.append(
            {
                "observation": index,
                "url": url,
                "error": error_text,
            }
        )

    if index % 25 == 0 or index == len(rows):
        print(
            f"Processed {index}/{len(rows)}"
        )

    time.sleep(INTER_OBSERVATION_DELAY)


experiment_end = time.perf_counter()

network_end = safe_net_io()


# ============================================================
# WRITE RAW RESULTS
# ============================================================

fieldnames = [
    "observation",
    "sample_id",
    "url",
    "ground_truth",
    "decision",
    "risk",
    "latency_ms",
    "cpu_percent_total_capacity",
    "memory_before_mb",
    "memory_after_mb",
    "memory_peak_observed_mb",
    "latency_under_2_seconds",
    "cpu_under_15_percent",
    "memory_under_300_mb",
    "error",
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
    writer.writerows(results)


# ============================================================
# CALCULATE SUMMARY STATISTICS
# ============================================================

successful = [
    row for row in results
    if not row["error"]
]

latencies = [
    float(row["latency_ms"])
    for row in successful
]

cpu_values = [
    float(row["cpu_percent_total_capacity"])
    for row in successful
]

memory_values = [
    float(row["memory_peak_observed_mb"])
    for row in successful
]


if latencies:
    latency_mean = statistics.mean(latencies)
    latency_median = statistics.median(latencies)
    latency_p95 = percentile(latencies, 95)
    latency_max = max(latencies)
else:
    latency_mean = 0.0
    latency_median = 0.0
    latency_p95 = 0.0
    latency_max = 0.0


if cpu_values:
    cpu_mean = statistics.mean(cpu_values)
    cpu_median = statistics.median(cpu_values)
    cpu_p95 = percentile(cpu_values, 95)
    cpu_peak = max(cpu_values)
else:
    cpu_mean = 0.0
    cpu_median = 0.0
    cpu_p95 = 0.0
    cpu_peak = 0.0


if memory_values:
    memory_mean = statistics.mean(memory_values)
    memory_median = statistics.median(memory_values)
    memory_peak = max(memory_values)
else:
    memory_mean = 0.0
    memory_median = 0.0
    memory_peak = 0.0


latency_pass_count = sum(
    1
    for row in successful
    if row["latency_under_2_seconds"]
)

cpu_pass_count = sum(
    1
    for row in successful
    if row["cpu_under_15_percent"]
)

memory_pass_count = sum(
    1
    for row in successful
    if row["memory_under_300_mb"]
)


successful_count = len(successful)

if successful_count:
    latency_pass_rate = (
        latency_pass_count
        / successful_count
        * 100.0
    )

    cpu_pass_rate = (
        cpu_pass_count
        / successful_count
        * 100.0
    )

    memory_pass_rate = (
        memory_pass_count
        / successful_count
        * 100.0
    )
else:
    latency_pass_rate = 0.0
    cpu_pass_rate = 0.0
    memory_pass_rate = 0.0


bytes_sent = max(
    0,
    network_end["bytes_sent"]
    - network_start["bytes_sent"],
)

bytes_recv = max(
    0,
    network_end["bytes_recv"]
    - network_start["bytes_recv"],
)

total_network_bytes = (
    bytes_sent + bytes_recv
)

experiment_duration_seconds = (
    experiment_end - experiment_start
)


# ============================================================
# H3 THRESHOLD ASSESSMENT
# ============================================================

cpu_mean_pass = (
    cpu_mean < CPU_THRESHOLD
)

memory_peak_pass = (
    memory_peak < MEMORY_THRESHOLD_MB
)

latency_p95_pass = (
    latency_p95 < LATENCY_THRESHOLD_MS
)


# ============================================================
# CREATE SUMMARY
# ============================================================

summary = []

summary.append("=" * 72)
summary.append(
    "PHISHGUARD H3 OPERATIONAL PERFORMANCE EXPERIMENT"
)
summary.append("=" * 72)
summary.append("")

summary.append(f"Dataset: {DATASET}")
summary.append(
    f"Total observations: {len(rows)}"
)
summary.append(
    f"Successful observations: {successful_count}"
)
summary.append(
    f"Errors: {len(errors)}"
)
summary.append("")

summary.append("CONFIGURATION")
summary.append("-" * 72)
summary.append(
    "Engine: PhishGuard v2.3 EnhancedPhishGuardEngine"
)
summary.append("Threat intelligence: OFF")
summary.append("TLS analysis: ON")
summary.append(
    f"Logical CPU count used for normalization: {logical_cpus}"
)
summary.append(
    f"Inter-observation delay: "
    f"{INTER_OBSERVATION_DELAY:.2f} seconds"
)
summary.append("")

summary.append("ENGINEERING ACCEPTANCE THRESHOLDS")
summary.append("-" * 72)
summary.append(
    f"CPU utilization: < {CPU_THRESHOLD:.2f}%"
)
summary.append(
    f"Memory utilization: < {MEMORY_THRESHOLD_MB:.2f} MB"
)
summary.append(
    f"Analysis latency: < {LATENCY_THRESHOLD_MS:.2f} ms"
)
summary.append("")

summary.append("ANALYSIS LATENCY")
summary.append("-" * 72)
summary.append(
    f"Mean:   {latency_mean:.3f} ms"
)
summary.append(
    f"Median: {latency_median:.3f} ms"
)
summary.append(
    f"P95:    {latency_p95:.3f} ms"
)
summary.append(
    f"Maximum: {latency_max:.3f} ms"
)
summary.append(
    f"Observations under 2 seconds: "
    f"{latency_pass_count}/{successful_count} "
    f"({latency_pass_rate:.2f}%)"
)
summary.append("")

summary.append("CPU UTILIZATION")
summary.append("-" * 72)
summary.append(
    f"Mean:   {cpu_mean:.3f}%"
)
summary.append(
    f"Median: {cpu_median:.3f}%"
)
summary.append(
    f"P95:    {cpu_p95:.3f}%"
)
summary.append(
    f"Peak:   {cpu_peak:.3f}%"
)
summary.append(
    f"Observations under 15%: "
    f"{cpu_pass_count}/{successful_count} "
    f"({cpu_pass_rate:.2f}%)"
)
summary.append("")

summary.append("MEMORY UTILIZATION")
summary.append("-" * 72)
summary.append(
    f"Baseline RSS: {baseline_memory_mb:.3f} MB"
)
summary.append(
    f"Mean observed RSS: {memory_mean:.3f} MB"
)
summary.append(
    f"Median observed RSS: {memory_median:.3f} MB"
)
summary.append(
    f"Peak observed RSS: {memory_peak:.3f} MB"
)
summary.append(
    f"Observations under 300 MB: "
    f"{memory_pass_count}/{successful_count} "
    f"({memory_pass_rate:.2f}%)"
)
summary.append("")

summary.append("NETWORK ACTIVITY")
summary.append("-" * 72)
summary.append(
    f"Bytes sent during measured experiment: {bytes_sent}"
)
summary.append(
    f"Bytes received during measured experiment: {bytes_recv}"
)
summary.append(
    f"Total observed system network bytes: {total_network_bytes}"
)
summary.append("")
summary.append(
    "Network counters are system-wide interface counters and therefore "
    "are descriptive rather than PhishGuard-process-attributable."
)
summary.append(
    "TLS inspection may create destination-host network activity."
)
summary.append("")

summary.append("EXPERIMENT DURATION")
summary.append("-" * 72)
summary.append(
    f"Measured workload duration: "
    f"{experiment_duration_seconds:.3f} seconds"
)
summary.append("")

summary.append("H3 THRESHOLD ASSESSMENT")
summary.append("-" * 72)
summary.append(
    f"Mean CPU < 15%: "
    f"{'PASS' if cpu_mean_pass else 'FAIL'}"
)
summary.append(
    f"Peak memory < 300 MB: "
    f"{'PASS' if memory_peak_pass else 'FAIL'}"
)
summary.append(
    f"P95 latency < 2 seconds: "
    f"{'PASS' if latency_p95_pass else 'FAIL'}"
)
summary.append("")

summary.append(
    "Primary H3 operational assessment uses mean CPU utilization, "
    "peak observed memory utilization, and P95 analysis latency."
)
summary.append(
    "Per-observation values are retained in the detailed CSV for "
    "engineering variability and outlier analysis."
)
summary.append("")

summary.append("=" * 72)
summary.append("H3 PERFORMANCE TEST COMPLETE")
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


# ============================================================
# DISPLAY SUMMARY
# ============================================================

print()
print(summary_text)
