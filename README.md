# PhishGuard

PhishGuard is an explainable phishing-detection research prototype developed as part of a Doctor of Engineering praxis.

The application evaluates URLs using multiple indicators, including URL structure, domain characteristics, lexical features, brand similarity, and optional TLS certificate analysis.

Its desktop interface uses Python, PySide6, and QtWebEngine.

## Research Objectives

The research evaluates four hypotheses:

- H1: PhishGuard detection compared with Chrome's observed phishing detection.
- H2: Multi-indicator scoring compared with isolated indicator families.
- H3: Operational performance, including latency, CPU utilization, and memory usage.
- H4: Local-only analysis compared with TLS-enabled analysis.

## Frozen Experimental Findings

### H1: Browser Comparison

200 observations were evaluated.

PhishGuard:
- Accuracy: 52%
- Phishing recall: 9%
- False-positive rate: 5%

PhishGuard uniquely detected 5 phishing observations.
Chrome uniquely detected 27 phishing observations.

Exact paired McNemar p-value: 0.000113.

The overall paired detection difference favored Chrome.

### H2: Multi-Indicator Analysis

Development dataset: 600 observations.
Validation dataset: 200 observations.

Full configuration:
- Development accuracy: 53%
- Development recall: 12%
- Validation accuracy: 54%
- Validation recall: 13%

The full configuration achieved higher observed accuracy and recall than the isolated configurations.

During validation, statistical significance was established only against the brand/lexical configuration.

### H3: Operational Performance

200 observations.

- Mean CPU utilization: 4.156%
- Peak observed memory: 118.625 MB
- 95th-percentile analysis latency: 1,023.903 ms
- Maximum analysis latency: 24,088.140 ms

All predefined operational acceptance criteria passed.

Seven observations exceeded two seconds.

### H4: Local Analysis

200 observations.

TLS-enabled condition:
- Accuracy: 54%
- Recall: 13%

Local-only condition:
- Accuracy: 51%
- Recall: 7%

Decision agreement between conditions: 97%.

The local-only condition does not establish that the complete desktop application operates fully offline.

## Technology

- Python 3.12
- PySide6 / QtWebEngine
- idna
- tldextract
- psutil

## Installation

Create a Python virtual environment and install dependencies:

    python3 -m venv venv
    source venv/bin/activate
    python -m pip install -r requirements.txt

The desktop application requires a compatible graphical environment.

Google Colab does not provide the same desktop QtWebEngine environment and is not a direct replacement for native desktop execution.

## Research Reproducibility

Frozen experimental datasets and outputs are preserved for research transparency.

The original experimental outputs should not be overwritten when reproducing or extending the experiments.

The H2 validation summary contains an interpretation-note inconsistency. The statistical results are preserved as originally recorded.

Threat-intelligence feeds are not redistributed in this repository pending verification of provider terms.

H2, H3, and H4 experiments were conducted with threat-intelligence matching disabled.

## Limitations

PhishGuard demonstrated low phishing recall under the evaluated frozen configurations.

Results should not be interpreted as evidence that PhishGuard outperformed Chrome overall.

The system is a research prototype and should not be relied upon as a sole phishing protection mechanism.
