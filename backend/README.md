# Backend Module - LLM Code Vulnerability Analysis Framework

This backend module provides comprehensive vulnerability detection, patching, and analysis capabilities for LLM-generated code.

## Features

### 🔍 Dynamic Vulnerability Detection
- **Multi-Strategy Detection**: Pattern-based, AST-based, and similarity-based detection
- **Comprehensive CWE Coverage**: Supports 34+ CWE categories dynamically
- **Smart Pattern Matching**: Regex patterns for quick vulnerability identification
- **AST Analysis**: Deep code structure analysis for complex vulnerabilities
- **Similarity Comparison**: Compare generated code with known vulnerable samples

### 💡 Explainability Layer
- **Detailed Explanations**: Plain-language descriptions for each vulnerability
- **Patch Recommendations**: Specific guidance on how to fix each issue
- **Remediation Priorities**: CRITICAL, HIGH, MEDIUM, LOW priority assignments
- **CWE Mapping**: Automatic mapping to CWE categories with descriptions

### 🔧 Automated Patching
- **Rule-Based Patching**: Automated fixes for common vulnerability patterns
- **LLM-Based Patching**: Use OpenAI for complex patching scenarios
- **Multi-CWE Support**: Handles SQL injection, path traversal, command injection, and more
- **Iterative Repair**: Multiple patching iterations until code is clean or reaches the max iterations.

### 🔬 Static Analysis
- **Bandit Integration**: Primary static analysis tool
- **Semgrep Integration**: Secondary validation tool
- **Cross-Validation**: Compare results from multiple tools
- **Detailed Reports**: Issue counts, severity breakdowns, confidence levels

### 📊 Metrics & Reporting
- **Effectiveness Metrics**: Precision, recall, F1-score, accuracy
- **Patching Success Rate**: Measure how many vulnerabilities were fixed
- **Tool Comparison**: Analyze detection overlap between tools
- **Export Formats**: HTML reports

## Module Structure

```
backend/
├── __init__.py                  # Module exports
├── workflow.py                  # Main workflow orchestrator
├── vuln_detection.py            # Vulnerability detection engine
├── explainability.py            # Explanation generation
├── patching.py                  # Code patching engine
├── static_analysis.py           # Bandit & Semgrep integration
├── metrics.py                   # Metrics calculation
├── reporting.py                 # Report generation
├── preprocessing.py             # Code cleaning and normalization
└── requirements.txt             # Dependencies
```

## Supported CWE Categories

The framework dynamically detects and patches 34+ CWE categories:

- **CWE-020**: Improper Input Validation
- **CWE-022**: Path Traversal
- **CWE-078**: OS Command Injection
- **CWE-089**: SQL Injection
- **CWE-094**: Code Injection
- **CWE-095**: Eval Injection
- **CWE-259**: Hard-coded Password
- **CWE-295**: Improper Certificate Validation
- **CWE-319**: Cleartext Transmission
- **CWE-326**: Weak Encryption
- **CWE-330**: Weak Random Values
- **CWE-502**: Deserialization
- **CWE-611**: XML External Entity (XXE)
- **CWE-798**: Hard-coded Credentials
- And 20+ more...

## Usage

### Quick Start

```python
from backend.workflow import VulnerabilityAnalysisWorkflow

# Initialize workflow
workflow = VulnerabilityAnalysisWorkflow(
    vulnerable_samples_dir="path/to/vulnerable/samples",
    reports_dir="reports",
    openai_client=your_openai_client,  # Optional
    max_patch_iterations=6
)

# Run complete analysis
results = workflow.run_complete_workflow(
    generated_code=llm_generated_code,
    prompt="Your prompt here"
)

# Access results
print(f"Status: {results['status']}")
print(f"Vulnerabilities found: {results['vulnerability_count']}")
print(f"Patching success: {results['metrics']['overall_success_rate']}")
```

### Individual Components

#### Vulnerability Detection

```python
from backend.vuln_detection import VulnerabilityDetector

detector = VulnerabilityDetector("path/to/vulnerable/samples")
vulnerabilities = detector.detect_vulnerabilities(code)

for vuln in vulnerabilities:
    print(f"CWE-{vuln['cwe_id']}: {vuln['cwe_name']}")
    print(f"Line {vuln['line_number']}: {vuln['description']}")
```

#### Code Patching

```python
from backend.patching import CodePatcher

patcher = CodePatcher(openai_client)
result = patcher.generate_patch(code, vulnerabilities)

print(f"Patched code:\n{result['patched_code']}")
print(f"Changes applied: {len(result['changes'])}")
```

#### Static Analysis

```python
from backend.static_analysis import StaticAnalyzer

analyzer = StaticAnalyzer()
bandit_results = analyzer.run_bandit(code)
semgrep_results = analyzer.run_semgrep(code)

print(f"Bandit issues: {len(bandit_results['issues'])}")
print(f"Semgrep issues: {len(semgrep_results['issues'])}")
```

## Installation

Install dependencies:

```bash
pip install -r backend/requirements.txt
```

Ensure static analysis tools are available:

```bash
# Verify Bandit installation
bandit --version

# Verify Semgrep installation
semgrep --version
```

## Workflow Steps

The complete workflow executes these steps automatically:

1. **Preprocessing**: Clean and normalize code
2. **Vulnerability Detection**: Detect vulnerabilities using multiple strategies
3. **Explainability**: Generate explanations and recommendations
4. **Initial Reporting**: Create vulnerability reports
5. **Patching**: Generate secure patched code
6. **Primary Static Analysis**: Validate with Bandit
7. **Secondary Analysis**: Cross-validate with Semgrep
8. **Iterative Repair**: Repeat patching if needed (up to max iterations)
9. **Final Analysis**: Run tools on final patched code
10. **Metrics Calculation**: Calculate effectiveness metrics
11. **Final Reporting**: Generate comprehensive reports

## Configuration

### Max Patch Iterations

Control how many times the system attempts to patch code:

```python
workflow = VulnerabilityAnalysisWorkflow(
    vulnerable_samples_dir="...",
    max_patch_iterations=6 
)
```

### OpenAI Integration

For LLM-based patching of complex vulnerabilities:

```python
from services import OpenAIClientWrapper

client = OpenAIClientWrapper(api_key="your-api-key")
workflow = VulnerabilityAnalysisWorkflow(
    vulnerable_samples_dir="...",
    openai_client=client
)
```

## Output Reports

The framework generates multiple report types:

- **Vulnerability Reports**: CSV and JSON with all detected issues
- **Patch Reports**: JSON with before/after code and changes
- **Code Diffs**: Unified diff format showing changes
- **Static Analysis Reports**: JSON with Bandit and Semgrep results
- **Metrics Reports**: JSON with effectiveness metrics
- **HTML Summary**: Human-readable HTML report

## Extending the Framework

### Adding New CWE Categories

1. Add CWE description in `vuln_detection.py` → `_get_cwe_name()`
2. Add detection pattern in `vuln_detection.py` → `_initialize_patterns()`
3. Add explanation in `explainability.py` → `_initialize_explanations()`
4. Add patch note in `explainability.py` → `_initialize_patch_notes()`
5. Add patch rule in `patching.py` → `_initialize_patch_rules()`

### Adding New Detection Strategies

Implement custom detection in `vuln_detection.py`:

```python
def _custom_detection_strategy(self, code: str) -> List[Dict]:
    """Your custom detection logic."""
    vulnerabilities = []
    # Your detection code here
    return vulnerabilities

# Add to detect_vulnerabilities method:
custom_vulns = self._custom_detection_strategy(generated_code)
detected_vulns.extend(custom_vulns)
```

## Performance

- **Detection Speed**: ~1-2 seconds for typical code snippets
- **Patching Speed**: ~2-5 seconds per iteration
- **Static Analysis**: ~3-5 seconds for Bandit + Semgrep
- **Total Workflow**: ~10-30 seconds depending on complexity

## Limitations

- Python code only (currently)
- Requires Bandit and Semgrep to be installed
- LLM-based patching requires OpenAI API access
- Pattern-based detection may have false positives
- AST analysis limited to syntactically valid code

## Contributing

To add new features or improve detection:

1. Add tests for your changes
2. Update documentation
3. Ensure backwards compatibility
4. Follow existing code patterns

## License

Part of the LLM Code Vulnerability Analysis & Mitigation Framework.
