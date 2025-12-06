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
    4. Patching: Generate secure patched code
    5. Static Analysis (Bandit): Validate with primary security tool
    6. Cross-validation (Semgrep): Validate with secondary tool
    7. Iterative Repair: Repeat patching if needed, incorporating all tool findings
    8. Final Static Analysis: Record final validation results
    9. Metrics: Calculate effectiveness metrics
    10. Final Reporting: Generate comprehensive reports
    """
    
    def __init__(
        self,
        vulnerable_samples_dir: str,
        reports_dir: str = "reports",
        openai_client=None,
        max_patch_iterations: int = 6
    ):
        """
        Initialize the workflow with necessary components.
        
        Args:
            vulnerable_samples_dir: Path to directory with vulnerable code samples
            reports_dir: Directory to save reports
            openai_client: OpenAI client for LLM-based patching
            max_patch_iterations: Maximum number of patching iterations
        """
        self.detector = VulnerabilityDetector(vulnerable_samples_dir)
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

        # Also run Bandit and Semgrep on the original (cleaned) code
        print("\n🔬 Initial Static Analysis on original code (Bandit & Semgrep)...")
        bandit_original = self._step_static_analysis_bandit(cleaned_code)
        semgrep_original = self._step_static_analysis_secondary(cleaned_code)
        results['bandit_original'] = bandit_original
        results['semgrep_original'] = semgrep_original

        # Initialize accumulator of all findings across iterations
        all_found_vulns: List[Dict] = []
        all_found_vulns.extend(vulnerabilities)
        all_found_vulns.extend(self._convert_bandit_to_vulns(bandit_original.get('issues', []) if bandit_original.get('success') else [], cleaned_code))
        all_found_vulns.extend(self._convert_semgrep_to_vulns(semgrep_original.get('issues', []) if semgrep_original.get('success') else [], cleaned_code))
        results['all_found_vulns_initial'] = list(all_found_vulns)
        
        if not vulnerabilities and not all_found_vulns:
            print("✅ No vulnerabilities detected by any tool on original code!")
            results['status'] = 'clean'
            return results
        
        # Detailed output of initial findings
        bandit_issues_count = len(bandit_original.get('issues', [])) if bandit_original.get('success') else 0
        semgrep_issues_count = len(semgrep_original.get('issues', [])) if semgrep_original.get('success') else 0
        
        print(f"\n⚠️  Initial Analysis Results:")
        print(f"   - Custom detector: {len(vulnerabilities)} vulnerabilities")
        if vulnerabilities:
            for vuln in vulnerabilities:
                cwe_id = vuln.get('cwe_id', 'Unknown')
                cwe_name = vuln.get('cwe_name', 'Unknown')
                line = vuln.get('line_number', 'Unknown')
                print(f"      • CWE-{cwe_id} ({cwe_name}) at line {line}")
        
        print(f"   - Bandit: {bandit_issues_count} issues")
        if bandit_original.get('success') and bandit_original.get('issues'):
            for issue in bandit_original.get('issues', [])[:10]:  # Limit to first 10
                test_id = issue.get('test_id', 'Unknown')
                test_name = issue.get('test_name', 'Unknown')
                line = issue.get('line_number', 'Unknown')
                severity = issue.get('severity', 'Unknown')
                print(f"      • {test_id} ({test_name}) at line {line} [{severity}]")
            if bandit_issues_count > 10:
                print(f"      ... and {bandit_issues_count - 10} more")
        
        print(f"   - Semgrep: {semgrep_issues_count} issues")
        if semgrep_original.get('success') and semgrep_original.get('issues'):
            for issue in semgrep_original.get('issues', [])[:10]:  # Limit to first 10
                check_id = issue.get('check_id', 'Unknown')
                message = issue.get('message', 'No description')
                line = issue.get('start', {}).get('line', issue.get('end', {}).get('line', 'Unknown'))
                severity = issue.get('severity', 'Unknown')
                # Truncate long messages
                if len(message) > 60:
                    message = message[:57] + "..."
                print(f"      • {check_id}: {message} at line {line} [{severity}]")
            if semgrep_issues_count > 10:
                print(f"      ... and {semgrep_issues_count - 10} more")
        
        print(f"\n   Total findings across all tools: {len(all_found_vulns)}")
        
        # Step 3: Explainability
        print("\n💡 Step 3: Generating explanations...")
        vulnerabilities = self._step_explainability(vulnerabilities)
        results['vulnerabilities_with_explanations'] = vulnerabilities
        
        # Step 4: Patching
        print("\n🔧 Step 4: Generating patches...")
        patch_result = self._step_patching(cleaned_code, vulnerabilities)
        results['patch_result'] = patch_result
        
        # Step 5: Static Analysis on Patched Code (Bandit)
        print("\n🔬 Step 5: Running Bandit analysis on patched code...")
        bandit_patched = self._step_static_analysis_bandit(patch_result['patched_code'])
        results['bandit_patched'] = bandit_patched
        
        # Step 6: Static Analysis on Patched Code (Semgrep)
        print("\n🔍 Step 6: Running Semgrep analysis on patched code...")
        secondary_patched = self._step_static_analysis_secondary(patch_result['patched_code'])
        results['secondary_patched'] = secondary_patched
        
        # Step 7: Iterative Repair (if needed)
        print("\n🔄 Step 7: Checking if additional patching needed...")
        current_code = patch_result['patched_code']
        all_iterations = [patch_result]
        bandit_final = bandit_patched
        secondary_final = secondary_patched
        
        # Start from 2 since we already have iteration 1 (initial patch)
        for iteration_count in range(2, self.max_patch_iterations + 1):
            # Check all three detection methods
            remaining_vulns = self._detect_remaining_vulnerabilities(current_code)
            bandit_issues = bandit_final.get('issues', []) if bandit_final.get('success') else []
            semgrep_issues = secondary_final.get('issues', []) if secondary_final.get('success') else []
            
            total_issues = len(remaining_vulns) + len(bandit_issues) + len(semgrep_issues)
            
            if total_issues == 0:
                print(f"✅ All vulnerabilities fixed after {iteration_count - 1} iteration(s)!")
                print(f"   - Custom detector: 0 vulnerabilities")
                print(f"   - Bandit: 0 issues")
                print(f"   - Semgrep: 0 issues")
                break
            
            print(f"🔄 Iteration {iteration_count}: {total_issues} total issues found")
            print(f"   - Custom detector: {len(remaining_vulns)} vulnerabilities")
            if remaining_vulns:
                for vuln in remaining_vulns:
                    cwe_id = vuln.get('cwe_id', 'Unknown')
                    cwe_name = vuln.get('cwe_name', 'Unknown')
                    line = vuln.get('line_number', vuln.get('line', 'Unknown'))
                    print(f"      • CWE-{cwe_id} ({cwe_name}) at line {line}")
            
            print(f"   - Bandit: {len(bandit_issues)} issues")
            if bandit_issues:
                for issue in bandit_issues:
                    test_id = issue.get('test_id', 'Unknown')
                    test_name = issue.get('test_name', 'Unknown')
                    line = issue.get('line_number', 'Unknown')
                    severity = issue.get('severity', 'Unknown')
                    print(f"      • {test_id} ({test_name}) at line {line} [{severity}]")
            
            print(f"   - Semgrep: {len(semgrep_issues)} issues")
            if semgrep_issues:
                for issue in semgrep_issues:
                    check_id = issue.get('check_id', 'Unknown')
                    message = issue.get('message', 'No description')
                    line = issue.get('start', {}).get('line', issue.get('end', {}).get('line', 'Unknown'))
                    severity = issue.get('severity', 'Unknown')
                    # Truncate long messages
                    if len(message) > 60:
                        message = message[:57] + "..."
                    print(f"      • {check_id}: {message} at line {line} [{severity}]")
            
            # Convert Bandit issues to vulnerability format for patching
            bandit_vulns = self._convert_bandit_to_vulns(bandit_issues, current_code)
            
            # Convert Semgrep issues to vulnerability format for patching
            semgrep_vulns = self._convert_semgrep_to_vulns(semgrep_issues, current_code)
            
            # Combine all vulnerabilities
            all_vulns = remaining_vulns + bandit_vulns + semgrep_vulns

            # Accumulate all found in this iteration
            all_found_vulns.extend(remaining_vulns)
            all_found_vulns.extend(bandit_vulns)
            all_found_vulns.extend(semgrep_vulns)
            
            if not all_vulns:
                print("✅ No vulnerabilities to patch!")
                break
            
            # Patch again with all detected issues
            # Store per-iteration custom detector findings for UI
            iteration_custom_vulns = {}
            for vuln in remaining_vulns:
                cwe_id = vuln.get('cwe_id', 'Unknown')
                cwe_name = vuln.get('cwe_name', 'Unknown')
                line = vuln.get('line_number', vuln.get('line', 'Unknown'))
                key = (cwe_id, cwe_name)
                if key not in iteration_custom_vulns:
                    iteration_custom_vulns[key] = {
                        'cwe_id': cwe_id,
                        'cwe_name': cwe_name,
                        'lines': [],
                        'explanations': []
                    }
                iteration_custom_vulns[key]['lines'].append(line)
                iteration_custom_vulns[key]['explanations'].append(vuln.get('explanation', ''))
            # Attach to iteration result for UI
            iteration_result = self._step_patching(current_code, all_vulns)
            iteration_result['custom_detector_vulns'] = iteration_custom_vulns
            all_iterations.append(iteration_result)
            current_code = iteration_result['patched_code']
            
            # Re-run static analysis on new patched code
            bandit_final = self._step_static_analysis_bandit(current_code)
            secondary_final = self._step_static_analysis_secondary(current_code)
        
        # Determine the actual iteration count (last iteration executed)
        results['total_iterations'] = len(all_iterations)
        results['patch_iterations'] = all_iterations
        results['final_patched_code'] = current_code
        
        # Step 8: Final Static Analysis (use latest results from loop)
        print("\n🔬 Step 8: Recording final static analysis results...")
        results['bandit_final'] = bandit_final
        results['secondary_final'] = secondary_final
        
        # Step 9: Evaluation and Metrics
        print("\n📈 Step 9: Calculating metrics...")
        # Combine vulnerabilities from all three tools
        bandit_final_vulns = self._convert_bandit_to_vulns(
            bandit_final.get('issues', []) if bandit_final.get('success') else [],
            current_code
        )
        semgrep_final_vulns = self._convert_semgrep_to_vulns(
            secondary_final.get('issues', []) if secondary_final.get('success') else [],
            current_code
        )
        
        # Remaining vulnerabilities = custom detector + Bandit + Semgrep on final patched code
        total_remaining_vulns = all_iterations[-1]['unpatched_vulns'] + bandit_final_vulns + semgrep_final_vulns

        # Add final detections to all_found accumulator
        all_found_vulns.extend(bandit_final_vulns)
        all_found_vulns.extend(semgrep_final_vulns)
        
        # Deduplicate all_found_vulns based on CWE + line + detection method
        # This prevents counting the same vulnerability multiple times across iterations
        seen_vulns = set()
        unique_found_vulns = []
        for vuln in all_found_vulns:
            vuln_key = (
                vuln.get('cwe_id', 'Unknown'),
                vuln.get('line', vuln.get('line_number', 'Unknown')),
                vuln.get('detection_method', vuln.get('source', 'Unknown'))
            )
            if vuln_key not in seen_vulns:
                seen_vulns.add(vuln_key)
                unique_found_vulns.append(vuln)
        
        results['all_found_vulns_total'] = unique_found_vulns
        
        metrics = self._step_calculate_metrics(
            unique_found_vulns,
            total_remaining_vulns,
            bandit_final,
            secondary_final
        )
        # Tool-wise detected counts across all iterations (deduped)
        bandit_detected = len([v for v in unique_found_vulns if v.get('detection_method') == 'bandit'])
        semgrep_detected = len([v for v in unique_found_vulns if v.get('detection_method') == 'semgrep'])
        metrics['bandit_initial'] = bandit_detected
        metrics['semgrep_initial'] = semgrep_detected
        results['metrics'] = metrics
        
        # Step 10: Final Reporting
        print("\n📄 Step 10: Generating final reports...")
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
    
    def _step_patching(self, code: str, vulnerabilities: List[Dict]) -> Dict:
        """Step 4: Generate patched code."""
        return self.patcher.generate_patch(code, vulnerabilities)
    
    def _step_static_analysis_bandit(self, code: str) -> Dict:
        """Step 5: Run Bandit static analysis."""
        return self.analyzer.run_bandit(code)
    
    def _step_static_analysis_secondary(self, code: str) -> Dict:
        """Step 6: Run secondary tool (Semgrep) analysis."""
        return self.analyzer.run_semgrep(code)
    
    def _detect_remaining_vulnerabilities(self, code: str) -> List[Dict]:
        """Detect vulnerabilities in code (used for iteration checks)."""
        vulns = self.detector.detect_vulnerabilities(code)
        return self.explainer.generate_explanations(vulns)
    
    def _convert_bandit_to_vulns(self, bandit_issues: List[Dict], code: str) -> List[Dict]:
        """
        Convert Bandit issues to vulnerability format for patching.
        
        Args:
            bandit_issues: List of issues from Bandit analysis
            code: The source code being analyzed
            
        Returns:
            List of vulnerabilities in standard format
        """
        vulnerabilities = []
        code_lines = code.split('\n')
        
        for issue in bandit_issues:
            line_num = issue.get('line_number', 0)
            snippet = code_lines[line_num - 1] if 0 < line_num <= len(code_lines) else ''
            
            # Map Bandit test_id to CWE if available
            cwe_id = issue.get('cwe_id') or self._map_bandit_test_to_cwe(issue.get('test_id', ''))
            
            vuln = {
                'cwe_id': cwe_id,
                'cwe_name': issue.get('test_name', 'Unknown'),
                'severity': issue.get('severity', 'MEDIUM').lower(),
                'confidence': issue.get('confidence', 'MEDIUM'),
                'line': line_num,
                'snippet': snippet,
                'description': issue.get('issue_text', 'Security issue detected by Bandit'),
                'explanation': f"Bandit {issue.get('test_id', '')}: {issue.get('issue_text', '')}",
                'source': 'bandit',
                'detection_method': 'bandit'
            }
            vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _convert_semgrep_to_vulns(self, semgrep_issues: List[Dict], code: str) -> List[Dict]:
        """
        Convert Semgrep issues to vulnerability format for patching.
        
        Args:
            semgrep_issues: List of issues from Semgrep analysis
            code: The source code being analyzed
            
        Returns:
            List of vulnerabilities in standard format
        """
        vulnerabilities = []
        code_lines = code.split('\n')
        
        for issue in semgrep_issues:
            line_num = issue.get('start', {}).get('line', 0) or issue.get('end', {}).get('line', 0)
            snippet = code_lines[line_num - 1] if 0 < line_num <= len(code_lines) else ''
            
            cwe_id = issue.get('cwe_id') or self._map_semgrep_check_to_cwe(issue.get('check_id', ''))
            
            vuln = {
                'cwe_id': cwe_id,
                'cwe_name': self.detector._get_cwe_name(cwe_id) if cwe_id else 'Unknown',
                'severity': issue.get('severity', 'MEDIUM').lower(),
                'confidence': 'MEDIUM',
                'line': line_num,
                'snippet': snippet,
                'description': issue.get('message', 'Issue detected by Semgrep'),
                'explanation': f"Semgrep {issue.get('check_id', '')}: {issue.get('message', '')}",
                'source': 'semgrep',
                'detection_method': 'semgrep'
            }
            vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _map_bandit_test_to_cwe(self, test_id: str) -> str:
        """Map Bandit test IDs to CWE identifiers."""
        mapping = {
            'B201': '502',  # pickle usage
            'B301': '502',  # pickle usage
            'B302': '502',  # marshal usage
            'B303': '937',  # MD5 usage
            'B304': '326',  # weak crypto
            'B305': '326',  # weak cipher
            'B306': '377',  # mktemp usage
            'B307': '78',   # eval usage
            'B308': '94',   # mark_safe usage
            'B310': '22',   # urllib.urlopen
            'B311': '330',  # random usage
            'B312': '78',   # telnetlib
            'B313': '94',   # exec usage
            'B314': '94',   # execfile usage
            'B315': '94',   # exec usage
            'B316': '94',   # exec usage
            'B317': '94',   # exec usage
            'B318': '94',   # exec usage
            'B319': '94',   # exec usage
            'B320': '94',   # exec usage
            'B321': '367',  # FTP usage
            'B322': '78',   # input usage
            'B323': '703',  # unverified context
            'B324': '326',  # hashlib MD5/SHA1
            'B401': '94',   # import telnetlib
            'B402': '94',   # import FTP
            'B403': '94',   # import pickle
            'B404': '78',   # import subprocess
            'B405': '94',   # import lxml
            'B406': '94',   # import lxml
            'B407': '94',   # import lxml
            'B408': '94',   # import lxml
            'B409': '94',   # import lxml
            'B410': '94',   # import lxml
            'B411': '94',   # import lxml
            'B412': '94',   # import lxml
            'B501': '295',  # request verify=False
            'B502': '295',  # SSL/TLS issues
            'B503': '295',  # SSL/TLS issues
            'B504': '295',  # SSL/TLS issues
            'B505': '326',  # weak crypto
            'B506': '522',  # yaml.load
            'B507': '78',   # ssh no host key verification
            'B601': '78',   # paramiko exec
            'B602': '78',   # shell=True
            'B603': '78',   # subprocess without shell
            'B604': '78',   # shell=True
            'B605': '78',   # shell=True
            'B606': '78',   # shell=True
            'B607': '78',   # partial path
            'B608': '89',   # SQL hardcoded
            'B609': '78',   # wildcard injection
            'B610': '89',   # django SQL
            'B611': '89',   # django SQL
            'B701': '327',  # jinja2 autoescape
            'B702': '798',  # Mako templates
            'B703': '327',  # django mark_safe
        }
        return mapping.get(test_id, '1035')  # Default to CWE-1035 (Vulnerable Third Party Component)
    
    def _map_semgrep_check_to_cwe(self, check_id: str) -> str:
        """Map Semgrep check IDs to CWE identifiers when possible."""
        mapping = {
            'python.lang.security.use-of-eval': '095',
            'python.lang.security.use-of-exec': '094',
            'python.sqlalchemy.security.sql-injection': '089',
            'python.flask.security.insecure-os-system': '078',
            'python.flask.security.path-traversal-open': '022',
            'python.yaml.security.insecure-load': '502',
            'python.requests.security.insecure-ssl-no-verify': '295',
            'python.jinja2.security.autoescape-disabled': '327',
        }
        return mapping.get(check_id, '1035')
    
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
        """Step 10: Generate all final reports."""
        reports = {}
        
        # Export iteration codes
        if 'patch_iterations' in results:
            reports['iteration_codes'] = self.reporter.export_iteration_codes(
                results['patch_iterations'],
                f"{workflow_id}_patch"
            )
        
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
                results.get('metrics', {}),
                results.get('original_code', ''),
                results.get('final_patched_code', '')
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
