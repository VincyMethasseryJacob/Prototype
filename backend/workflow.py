"""
Workflow Orchestrator: Manages the complete vulnerability analysis workflow.

This module coordinates all steps from code generation through patching and validation.
"""

from typing import Dict, List, Optional
import os
from datetime import datetime

from .vuln_detection import VulnerabilityDetector
from .explainability import VulnerabilityExplainer
from .patching import CodePatcher
from .static_analysis import StaticAnalyzer
from .metrics import MetricsCalculator
from .reporting import VulnerabilityReporter
from .preprocessing import clean_code


class VulnerabilityAnalysisWorkflow:
    """
    Orchestrates the complete workflow for vulnerability analysis, patching, and validation.
    
    Workflow Steps:
    1. Preprocessing: Clean and normalize generated code
    2. Vulnerability Detection: Detect vulnerabilities using multiple strategies
    3. Explainability: Generate explanations for each vulnerability
    4. Reporting: Create detailed reports
    5. Patching: Generate secure patched code
    6. Static Analysis: Validate with Bandit and secondary tools
    7. Iterative Repair: Repeat patching if needed
    8. Metrics: Calculate effectiveness metrics
    """
    
    def __init__(
        self,
        vulnerable_samples_dir: str,
        reports_dir: str = "reports",
        openai_client=None,
        max_patch_iterations: int = 25
    ):
        """
        Initialize the workflow with necessary components.
        
        Args:
            vulnerable_samples_dir: Path to directory with vulnerable code samples
            reports_dir: Directory to save reports
            openai_client: OpenAI client for LLM-based patching
            max_patch_iterations: Maximum number of patching iterations
        """
        self.detector = VulnerabilityDetector(vulnerable_samples_dir, openai_client=openai_client)
        self.explainer = VulnerabilityExplainer()
        self.patcher = CodePatcher(openai_client)
        self.analyzer = StaticAnalyzer()
        self.metrics_calc = MetricsCalculator()
        self.reporter = VulnerabilityReporter(reports_dir)
        self.max_patch_iterations = max_patch_iterations
        
        # Workflow state
        self.workflow_state = {}
    
    def run_complete_workflow(
        self,
        generated_code: str,
        prompt: str = "",
        workflow_id: str = None
    ) -> Dict:
        """
        Execute the complete vulnerability analysis workflow.
        
        Returns:
            Dict containing all results from each workflow step
        """
        if not workflow_id:
            workflow_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        results = {
            'workflow_id': workflow_id,
            'timestamp': datetime.now().isoformat(),
            'prompt': prompt,
            'original_code': generated_code
        }
        
        print(f"🚀 Starting workflow {workflow_id}...")
        
        # Step 1: Preprocessing
        print("\n📋 Step 1: Preprocessing code...")
        cleaned_code = self._step_preprocessing(generated_code)
        results['cleaned_code'] = cleaned_code
        
        # Step 2: Vulnerability Detection
        print("\n🔍 Step 2: Detecting vulnerabilities...")
        vulnerabilities = self._step_vulnerability_detection(cleaned_code)
        results['vulnerabilities_detected'] = vulnerabilities
        results['vulnerability_count'] = len(vulnerabilities)
        
        if not vulnerabilities:
            print("✅ No vulnerabilities detected!")
            results['status'] = 'clean'
            return results
        
        print(f"⚠️  Found {len(vulnerabilities)} vulnerabilities")
        
        # Step 3: Explainability
        print("\n💡 Step 3: Generating explanations...")
        vulnerabilities = self._step_explainability(vulnerabilities)
        results['vulnerabilities_with_explanations'] = vulnerabilities
        
        # Step 4: Initial Reporting
        print("\n📊 Step 4: Generating initial reports...")
        report_paths = self._step_initial_reporting(vulnerabilities, workflow_id)
        results['initial_reports'] = report_paths
        
        # Step 5: Patching
        print("\n🔧 Step 5: Generating patches...")
        patch_result = self._step_patching(cleaned_code, vulnerabilities)
        results['patch_result'] = patch_result
        
        # Step 6: Static Analysis (Primary - Bandit)
        print("\n🔬 Step 6: Running Bandit analysis...")
        bandit_original = self._step_static_analysis_bandit(cleaned_code)
        bandit_patched = self._step_static_analysis_bandit(patch_result['patched_code'])
        results['bandit_original'] = bandit_original
        results['bandit_patched'] = bandit_patched
        
        # Step 7: Cross-validation (Secondary Tool - Pylint)
        print("\n🔍 Step 7: Running cross-validation with secondary tool...")
        secondary_original = self._step_static_analysis_secondary(cleaned_code)
        secondary_patched = self._step_static_analysis_secondary(patch_result['patched_code'])
        results['secondary_original'] = secondary_original
        results['secondary_patched'] = secondary_patched
        
        # Step 8: Iterative Repair (if needed)
        print("\n🔄 Step 8: Checking if additional patching needed...")
        iteration_count = 1
        current_code = patch_result['patched_code']
        all_iterations = [patch_result]
        
        while iteration_count < self.max_patch_iterations:
            remaining_vulns = self._detect_remaining_vulnerabilities(current_code)
            
            if not remaining_vulns:
                print(f"✅ All vulnerabilities fixed after {iteration_count} iteration(s)!")
                break
            
            print(f"🔄 Iteration {iteration_count + 1}: {len(remaining_vulns)} vulnerabilities remain")
            
            # Patch again
            iteration_result = self._step_patching(current_code, remaining_vulns)
            all_iterations.append(iteration_result)
            current_code = iteration_result['patched_code']
            iteration_count += 1
        
        results['patch_iterations'] = all_iterations
        results['total_iterations'] = iteration_count
        results['final_patched_code'] = current_code
        
        # Step 9: Final Static Analysis
        print("\n🔬 Step 9: Running final static analysis...")
        bandit_final = self._step_static_analysis_bandit(current_code)
        secondary_final = self._step_static_analysis_secondary(current_code)
        results['bandit_final'] = bandit_final
        results['secondary_final'] = secondary_final
        
        # Step 10: Evaluation and Metrics
        print("\n📈 Step 10: Calculating metrics...")
        metrics = self._step_calculate_metrics(
            vulnerabilities,
            all_iterations[-1]['unpatched_vulns'],
            bandit_patched,
            secondary_patched
        )
        results['metrics'] = metrics
        
        # Step 11: Final Reporting
        print("\n📄 Step 11: Generating final reports...")
        final_reports = self._step_final_reporting(
            results,
            workflow_id
        )
        results['final_reports'] = final_reports
        
        # Determine overall status
        if not all_iterations[-1]['unpatched_vulns']:
            results['status'] = 'fully_patched'
            print("\n✅ Workflow completed successfully - all vulnerabilities patched!")
        else:
            results['status'] = 'partially_patched'
            print(f"\n⚠️  Workflow completed - {len(all_iterations[-1]['unpatched_vulns'])} vulnerabilities remain")
        
        return results
    
    def _step_preprocessing(self, code: str) -> str:
        """Step 1: Clean and normalize code."""
        return clean_code(code)
    
    def _step_vulnerability_detection(self, code: str) -> List[Dict]:
        """Step 2: Detect vulnerabilities."""
        return self.detector.detect_vulnerabilities(code)
    
    def _step_explainability(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """Step 3: Generate explanations for vulnerabilities."""
        return self.explainer.generate_explanations(vulnerabilities)
    
    def _step_initial_reporting(self, vulnerabilities: List[Dict], workflow_id: str) -> Dict:
        """Step 4: Generate initial vulnerability reports."""
        return self.reporter.export_vulnerability_report(
            vulnerabilities,
            f"{workflow_id}_initial"
        )
    
    def _step_patching(self, code: str, vulnerabilities: List[Dict]) -> Dict:
        """Step 5: Generate patched code."""
        return self.patcher.generate_patch(code, vulnerabilities)
    
    def _step_static_analysis_bandit(self, code: str) -> Dict:
        """Step 6: Run Bandit static analysis."""
        return self.analyzer.run_bandit(code)
    
    def _step_static_analysis_secondary(self, code: str) -> Dict:
        """Step 7: Run secondary tool (Pylint) analysis."""
        return self.analyzer.run_pylint(code)
    
    def _detect_remaining_vulnerabilities(self, code: str) -> List[Dict]:
        """Detect vulnerabilities in code (used for iteration checks)."""
        vulns = self.detector.detect_vulnerabilities(code)
        return self.explainer.generate_explanations(vulns)
    
    def _step_calculate_metrics(
        self,
        original_vulns: List[Dict],
        remaining_vulns: List[Dict],
        bandit_results: Dict,
        secondary_results: Dict
    ) -> Dict:
        """Step 10: Calculate comprehensive metrics."""
        return self.metrics_calc.calculate_comprehensive_metrics(
            original_vulns,
            remaining_vulns,
            bandit_results,
            secondary_results
        )
    
    def _step_final_reporting(self, results: Dict, workflow_id: str) -> Dict:
        """Step 11: Generate all final reports."""
        reports = {}
        
        # Patch report
        if 'patch_iterations' in results:
            last_patch = results['patch_iterations'][-1]
            reports['patch_report'] = self.reporter.export_patch_report(
                results['cleaned_code'],
                results['final_patched_code'],
                last_patch['changes'],
                last_patch['unpatched_vulns'],
                f"{workflow_id}_patch"
            )
        
        # Static analysis report
        if 'bandit_final' in results and 'secondary_final' in results:
            comparison = self.analyzer.compare_results(
                results['bandit_final'],
                results['secondary_final']
            )
            reports['static_analysis'] = self.reporter.export_static_analysis_report(
                results['bandit_final'],
                results['secondary_final'],
                comparison,
                f"{workflow_id}_static"
            )
        
        # Metrics report
        if 'metrics' in results:
            reports['metrics'] = self.reporter.export_metrics_report(
                results['metrics'],
                f"{workflow_id}_metrics"
            )
        
        # HTML summary
        if 'vulnerabilities_with_explanations' in results:
            reports['html_summary'] = self.reporter.generate_html_summary(
                results['vulnerabilities_with_explanations'],
                reports.get('patch_report', {}),
                results.get('metrics', {})
            )
        
        return reports
    
    def get_summary(self, results: Dict) -> Dict:
        """
        Generate a concise summary of workflow results.
        """
        return {
            'workflow_id': results.get('workflow_id'),
            'status': results.get('status'),
            'vulnerabilities_detected': results.get('vulnerability_count', 0),
            'vulnerabilities_fixed': len(results.get('vulnerabilities_detected', [])) - len(results.get('patch_result', {}).get('unpatched_vulns', [])),
            'patch_iterations': results.get('total_iterations', 0),
            'overall_success_rate': results.get('metrics', {}).get('overall_success_rate', 0),
            'reports_generated': list(results.get('final_reports', {}).keys())
        }
