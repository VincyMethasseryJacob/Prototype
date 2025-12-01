# Security Evaluation Prototype

A prototype security-evaluation pipeline and dataset for collecting, analyzing, and comparing insecure Python code examples.

## Table of Contents

- [Overview](#overview)
- [Files and Functions](#files-and-functions)
- [Recreate the Dataset](#recreate-the-dataset)
- [Analysis Results](#analysis-results)
- [Streamlit App](#streamlit-app)
- [Development Notes](#development-notes)
- [Citation](#citation)

## Overview

This repository contains scripts, notebooks, and example code used to build a dataset of insecure Python snippets (organized by CWE), run static analyzers (for example, Bandit), and merge analyzer output with dataset metadata for evaluation and research.

## Files and Functions

- `pyproject.toml` — project configuration and dependencies.
- `README.md` — this file (project overview and usage notes).
- `Security_PipelineDev.ipynb` — pipeline development notebook that parses dataset metadata, normalizes CWE IDs, and merges Bandit output with dataset metadata.
- `SecurityEval-main/DatasetCreator.py` — dataset creation script. Reads prompts and insecure examples and writes `SecurityEval-main/dataset.jsonl` (one JSON object per line).
- `SecurityEval-main/dataset.jsonl` — generated dataset (JSON Lines).
- `SecurityEval-main/Testcases_Insecure_Code/` — insecure example code organized by CWE.
- `Author_Insecure_Code/` — collected human-written insecure samples organized by CWE.
- `Notebooks/DataCollection.ipynb` — helper notebook for collecting and preparing insecure code examples.
- `SecurityEval-main/Result/` — analyzer outputs and related CSVs (e.g., Bandit scan results).

Example analyzer result files (in `SecurityEval-main/Result/`):
- `bandit_analysis_20251104_120350.csv` — Bandit scan output (example findings: use of `exec`, shell use in `subprocess`, temp-file issues, hardcoded credentials).
- `bandit_analysis_20251104_190136.csv` — additional Bandit scan output.

## Recreate the Dataset

To (re)create the dataset using the provided script, run this from the repository root in PowerShell:

```powershell
python SecurityEval-main/DatasetCreator.py
```

The script reads prompts from `SecurityEval-main/Testcases_Prompt/` and insecure examples from `SecurityEval-main/Testcases_Insecure_Code/` and writes `SecurityEval-main/dataset.jsonl`.

## Analysis Results

Analyzer output (CSV/JSON) is stored under `SecurityEval-main/Result/`. Use these files to inspect static-analysis findings and to compare tool outputs with the dataset ground truth.

## Streamlit App

There is a prototype UI under the `Streamlit app/` folder. To run the Streamlit demo locally:

```powershell
streamlit run "Streamlit app/app_main.py"
```

### Key Features

#### 1. Vulnerability Detection
The app detects vulnerabilities in LLM-generated code using:
- **Pattern-based detection**: Regex patterns matching known vulnerability signatures
- **AST-based analysis**: Abstract Syntax Tree analysis for detecting:
  - SQL Injection
  - Command Injection
  - Code Generation (eval/exec)
  - Path Traversal
  - Hardcoded Credentials
  - Unsafe Deserialization
  - Exception Handling Issues

The detector maps detected vulnerabilities to **34 CWE (Common Weakness Enumeration) categories** including:
- CWE-020: Improper Input Validation
- CWE-022: Path Traversal
- CWE-078: OS Command Injection
- CWE-089: SQL Injection
- CWE-094/095: Code Generation/Eval
- CWE-200/798: Hardcoded Credentials
- CWE-502: Unsafe Deserialization
- And 26 more...

#### 2. Explainability Layer
For each detected vulnerability, the system automatically generates:
- **Plain-language explanation**: Describes why the vulnerability is a security risk
  - Example: "SQL Injection occurs when user input is concatenated directly into SQL queries. An attacker can modify query logic, bypass authentication, extract data, or modify/delete data."
- **Patch recommendation**: Specific fix instructions
  - Example: "Use parameterized queries or prepared statements instead of string concatenation or formatting."

All explanations are stored in the output report and displayed alongside the vulnerability findings.

#### 3. Vulnerability Reporting
Comprehensive reporting with multiple export formats:

**Display Features:**
- **Summary Table**: Shows CWE ID, description, priority, severity, and line number
- **Detailed Findings**: Severity-colored visualization with expandable details for each vulnerability
- **No Vulnerabilities**: Clear "No vulnerabilities detected" message when code is secure

**Export Formats:**
- **CSV Export**: Tabular format with all vulnerability details and explanations
- **JSON Export**: Structured data for programmatic analysis
- Both formats include:
  - CWE ID and Name
  - Severity Level (Critical, High, Medium, Low)
  - Priority Score
  - Line Number
  - Matched Code
  - Plain-language Explanation
  - Patch Recommendation

**Report Statistics:**
- Total vulnerability count
- Count by severity level
- Unique CWE categories found
- Timestamp and metadata

### Workflow

1. **Input Generation**:
   - Enter a custom prompt or select from the SecurityEval dataset
   - App generates Python code using OpenAI API

2. **Vulnerability Analysis**:
   - Generated code is automatically scanned for security issues
   - Multiple detection methods analyze the code

3. **Results Display**:
   - Summary statistics shown immediately
   - Detailed table with all findings
   - Expandable sections for each vulnerability with full context

4. **Export & Download**:
   - Download reports in JSON or CSV format
   - Store for further analysis or compliance documentation

### New Modules

- **`VulnerabilityDetector`** (`services/vulnerability_detector.py`): Detects vulnerabilities using pattern and AST-based analysis
- **`ExplainabilityGenerator`** (`services/explainability_generator.py`): Generates explanations and patch recommendations
- **`VulnerabilityReporter`** (`services/vulnerability_reporter.py`): Generates and exports reports in multiple formats

## Development Notes

- Notebook `Security_PipelineDev.ipynb` contains utilities for normalizing CWE IDs (zero-padding to three digits) and merging Bandit results with dataset metadata.
- The repository contains two collections of insecure examples: `Author_Insecure_Code/` (human-collected) and `SecurityEval-main/Testcases_Insecure_Code/` (dataset examples).
