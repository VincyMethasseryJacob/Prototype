# LLM Code Vulnerability Analysis & Mitigation (CVAM) Prototype

A framework to detect, explain, patch, and validate security vulnerabilities in LLM‑generated Python code. Includes a backend analysis engine, a Streamlit UI, curated insecure samples by CWE, and tests.

## Table of Contents

- [Overview](#overview)
- [Project Structure](#project-structure)
- [Setup](#setup)
- [Quick Start](#quick-start)
- [Streamlit App](#streamlit-app)
- [Backend API](#backend-api)
- [Datasets](#datasets)
- [Testing](#testing)
- [Reports](#reports)
- [Notes](#notes)

## Overview

This repository provides:
- A backend module that performs vulnerability detection (pattern/AST/similarity), explainability, automated patching, and static analysis cross‑validation (Bandit, Semgrep).
- A Streamlit application to generate/analyze code, visualize findings, and export reports.
- Curated insecure SecurityEval Python dataset organized by CWE for evaluation.
- Tests and utilities to validate detection coverage and end‑to‑end workflow.

## Project Structure

- `backend/` — analysis engine: detection, explainability, patching, static analysis, metrics, reporting, and workflow orchestration.
- `Streamlit app/` — UI (Streamlit) and small service helpers.
- `Author_Insecure_Code/` — SecurityEval human‑written insecure samples by CWE (ground truth for evaluation).
- `SecurityEval-main/Testcases_Prompt/` — SecurityEval prompts used by the UI and experiments.
- `Notebooks/` — helper notebooks(e.g., data collection).
- `pyproject.toml` — project dependencies and Python version.
- `backend/requirements.txt` — backend and tool dependencies (Bandit, Semgrep, etc.).

## Setup

- Python: 3.12+
- OS: Windows supported (commands below use PowerShell)

Option A — use this repo’s venv (if present):

```powershell
# From repository root
.\Scripts\activate
pip install -r backend/requirements.txt
```

Option B — create a fresh virtual environment:

```powershell
python -m venv .venv
.\.venv\Scripts\activate
pip install -r backend/requirements.txt
```

Verify tools (recommended):

```powershell
bandit --version
semgrep --version
```

## Quick Start

Run the Streamlit UI:

```powershell
streamlit run "Streamlit app/app_main.py"
```

Or run the backend programmatically:

```python
from backend.workflow import VulnerabilityAnalysisWorkflow

workflow = VulnerabilityAnalysisWorkflow(
    vulnerable_samples_dir="Author_Insecure_Code",
    reports_dir="reports",
    openai_client=None,        # optional (rule-based patching if None)
    max_patch_iterations=6
)

code = """
import os, sqlite3
def f(user, path):
    q = "SELECT * FROM users WHERE name='" + user + "'"
    sqlite3.connect('db.db').cursor().execute(q)
    open(path).read()
    pwd = "admin123"
"""

results = workflow.run_complete_workflow(code, prompt="demo")
print(results["status"], results["vulnerability_count"])
```

Optional: LLM-based patching in the app can use the OpenAI API key. The UI provides a input field to enter it; no environment variable is required.

## Streamlit App

Launch:

```powershell
streamlit run "Streamlit app/app_main.py"
```

Features:
- Vulnerability detection using pattern and AST analysis across 30+ CWE categories.
- Explainability: plain‑language descriptions and patch recommendations.
- Reporting: summary + detailed findings, JSON export, basic stats.
- Integrates backend workflow for iterative patching and validation.

Relevant UI services:
- `services/audit_manager.py` — audit record helpers.
- `services/cwe_fetcher.py` — CWE label utilities.
- `services/openai_client_wrapper.py` — OpenAI client wrapper.
- `services/security_eval_loader.py` — loads prompt/examples from SecurityEval.

## Backend API

See the detailed module guide in backend/README.md. Key modules:
- `workflow.py` — orchestrates preprocessing → detection → explanations → patching → multi‑tool analysis → metrics → reports.
- `vuln_detection.py` — vulnerability detector (patterns, AST, similarity).
- `explainability.py` — explanation and patch‑note generation.
- `patching.py` — automated rule‑based patching.
- `static_analysis.py` — Bandit and Semgrep integration + comparisons.
- `metrics.py` — precision/recall/F1 and workflow metrics.
- `reporting.py` — CSV/JSON/HTML report generation.
- `preprocessing.py` — code cleanup/normalization.

Install backend requirements:

```powershell
pip install -r backend/requirements.txt
```

## Datasets

- `Author_Insecure_Code/` — curated insecure Python files grouped by CWE (used for evaluation and similarity).
- `SecurityEval-main/Testcases_Prompt/` — example prompts/testcases referenced by the UI.

## Reports

- Streamlit exports: JSON under `Streamlit app/audit_records/`.

## Notes

- Python only at present; static analysis relies on Bandit and Semgrep.