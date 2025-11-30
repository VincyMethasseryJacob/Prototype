"""
Backend module for LLM Code Vulnerability Analysis Framework.

This module provides comprehensive vulnerability detection, patching, and analysis
capabilities for LLM-generated code.
"""

from .vuln_detection import VulnerabilityDetector, detect_vulnerabilities
from .explainability import VulnerabilityExplainer, generate_explanations
from .patching import CodePatcher, generate_patch
from .static_analysis import StaticAnalyzer, run_bandit, run_secondary_tool
from .metrics import MetricsCalculator, calculate_metrics
from .reporting import VulnerabilityReporter, export_report
from .preprocessing import clean_code

__all__ = [
    'VulnerabilityDetector',
    'VulnerabilityExplainer',
    'CodePatcher',
    'StaticAnalyzer',
    'MetricsCalculator',
    'VulnerabilityReporter',
    'detect_vulnerabilities',
    'generate_explanations',
    'generate_patch',
    'run_bandit',
    'run_secondary_tool',
    'calculate_metrics',
    'export_report',
    'clean_code'
]

__version__ = '1.0.0'
