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
    2. Vulnerability Detection: Detect vulnerabilities using custom detector
    3. Explainability: Generate explanations for each vulnerability
    4. Initial Patching: Generate secure patched code for detected vulnerabilities
    5. Multi-Tool Analysis: Analyze initial patched code with custom detector, Bandit, and Semgrep
    6. Iterative Repair: If any tool finds vulnerabilities, start iteration loop:
       - Iteration 1: Patch code with all vulnerabilities found in step 5
       - Iteration 2+: Re-analyze patched code with all three tools, patch if needed
       - Continue until all tools report 0 vulnerabilities or max iterations reached
    7. Final Static Analysis: Record final validation results from all tools
    8. Metrics: Calculate effectiveness metrics
    9. Final Reporting: Generate comprehensive reports
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

        # Initialize accumulators for tracking vulnerabilities across all phases
        # Initial code findings (raw counts - no dedup)
        bandit_initial_converted = self._convert_bandit_to_vulns(bandit_original.get('issues', []) if bandit_original.get('success') else [], cleaned_code)
        semgrep_initial_converted = self._convert_semgrep_to_vulns(semgrep_original.get('issues', []) if semgrep_original.get('success') else [], cleaned_code)
        
        # Store initial code raw counts per tool
        initial_custom_count = len(vulnerabilities)
        initial_bandit_count = len(bandit_initial_converted)
        initial_semgrep_count = len(semgrep_initial_converted)
        initial_total_count = initial_custom_count + initial_bandit_count + initial_semgrep_count
        
        results['initial_custom_count'] = initial_custom_count
        results['initial_bandit_count'] = initial_bandit_count
        results['initial_semgrep_count'] = initial_semgrep_count
        results['initial_total_count'] = initial_total_count
        
        # All findings accumulator (across initial + iterations)
        all_found_vulns: List[Dict] = []
        all_found_vulns.extend(vulnerabilities)
        all_found_vulns.extend(bandit_initial_converted)
        all_found_vulns.extend(semgrep_initial_converted)
        results['all_found_vulns_initial'] = list(all_found_vulns)
        # Store all occurrences (not deduped) for UI
        results['all_found_vulns_occurrences'] = list(all_found_vulns)
        
        # Calculate initial code findings (deduplicated by CWE + line)
        initial_code_deduped = self._deduplicate_vulns_by_line([vulnerabilities, bandit_initial_converted, semgrep_initial_converted])
        results['initial_code_deduped_count'] = len(initial_code_deduped)
        results['initial_code_deduped'] = initial_code_deduped
        
        # Debug: Print found items before dedup
        print(f"\n📊 DEBUG - Initial Code Deduplication:")
        print(f"   Custom detector found: {len(vulnerabilities)} items")
        if vulnerabilities:
            for v in vulnerabilities[:3]:
                print(f"      - CWE-{v.get('cwe_id')}, line {v.get('line_number', v.get('line'))}")
        print(f"   Bandit found: {len(bandit_initial_converted)} items")
        if bandit_initial_converted:
            for v in bandit_initial_converted[:3]:
                print(f"      - CWE-{v.get('cwe_id')}, line {v.get('line', v.get('line_number'))}")
        print(f"   Semgrep found: {len(semgrep_initial_converted)} items")
        if semgrep_initial_converted:
            for v in semgrep_initial_converted[:3]:
                print(f"      - CWE-{v.get('cwe_id')}, line {v.get('line', v.get('line_number'))}")
        print(f"   After deduplication by (CWE, line): {len(initial_code_deduped)} unique items")
        
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
        
        # Step 4: Initial Patching
        print("\n🔧 Step 4: Generating initial patch...")
        patch_result = self._step_patching(cleaned_code, vulnerabilities)
        results['initial_patch_result'] = patch_result
        current_code = patch_result['patched_code']
        
        # Step 5: Analyze Initial Patched Code with All Three Tools
        print("\n🔬 Step 5: Analyzing initial patched code with all tools...")
        print("   Running Custom detector...")
        remaining_vulns_custom = self._detect_remaining_vulnerabilities(current_code)
        
        print("   Running Bandit...")
        bandit_result = self._step_static_analysis_bandit(current_code)
        bandit_issues = bandit_result.get('issues', []) if bandit_result.get('success') else []
        
        print("   Running Semgrep...")
        semgrep_result = self._step_static_analysis_secondary(current_code)
        semgrep_issues = semgrep_result.get('issues', []) if semgrep_result.get('success') else []
        
        # Convert tool results to vulnerability format
        bandit_vulns = self._convert_bandit_to_vulns(bandit_issues, current_code)
        semgrep_vulns = self._convert_semgrep_to_vulns(semgrep_issues, current_code)
        
        # Calculate total issues found
        total_issues = len(remaining_vulns_custom) + len(bandit_issues) + len(semgrep_issues)
        
        print(f"\n   Analysis Results on Initial Patched Code:")
        print(f"   - Custom detector: {len(remaining_vulns_custom)} vulnerabilities")
        print(f"   - Bandit: {len(bandit_issues)} issues")
        print(f"   - Semgrep: {len(semgrep_issues)} issues")
        print(f"   - Total: {total_issues} issues")
        
        # Step 6: Iterative Repair (if needed)
        all_iterations = []
        iteration_findings = []
        iteration_custom_count = 0  # Track iterations custom detector findings
        iteration_bandit_count = 0   # Track iterations bandit findings
        iteration_semgrep_count = 0  # Track iterations semgrep findings
        bandit_final = bandit_result
        secondary_final = semgrep_result
        
        if total_issues == 0:
            print("\n✅ Initial patch successful - no vulnerabilities found by any tool!")
            results['patch_iterations'] = all_iterations
            results['total_iterations'] = 0
            results['final_patched_code'] = current_code
        else:
            print("\n🔄 Step 6: Starting iterative repair process...")
            print(f"🔄 Iteration 1: {total_issues} issues detected in initial patched code")
            
            # Display details for iteration 1
            if remaining_vulns_custom:
                for vuln in remaining_vulns_custom:
                    cwe_id = vuln.get('cwe_id', 'Unknown')
                    cwe_name = vuln.get('cwe_name', 'Unknown')
                    line = vuln.get('line_number', vuln.get('line', 'Unknown'))
                    print(f"      • CWE-{cwe_id} ({cwe_name}) at line {line}")
            
            if bandit_issues:
                for issue in bandit_issues:
                    test_id = issue.get('test_id', 'Unknown')
                    test_name = issue.get('test_name', 'Unknown')
                    line = issue.get('line_number', 'Unknown')
                    severity = issue.get('severity', 'Unknown')
                    print(f"      • {test_id} ({test_name}) at line {line} [{severity}]")
            
            if semgrep_issues:
                for issue in semgrep_issues:
                    check_id = issue.get('check_id', 'Unknown')
                    message = issue.get('message', 'No description')
                    line = issue.get('start', {}).get('line', issue.get('end', {}).get('line', 'Unknown'))
                    severity = issue.get('severity', 'Unknown')
                    if len(message) > 60:
                        message = message[:57] + "..."
                    print(f"      • {check_id}: {message} at line {line} [{severity}]")
            
            # Combine all vulnerabilities for iteration 1
            all_vulns = remaining_vulns_custom + bandit_vulns + semgrep_vulns
            
            # Accumulate findings across all iterations
            iteration_findings.extend(remaining_vulns_custom)
            iteration_findings.extend(bandit_vulns)
            iteration_findings.extend(semgrep_vulns)
            all_found_vulns.extend(remaining_vulns_custom)
            all_found_vulns.extend(bandit_vulns)
            all_found_vulns.extend(semgrep_vulns)
            
            # Track per-tool counts for iterations
            iteration_custom_count += len(remaining_vulns_custom)
            iteration_bandit_count += len(bandit_vulns)
            iteration_semgrep_count += len(semgrep_vulns)
            
            # Store custom detector findings for UI
            iteration_custom_vulns = {}
            for vuln in remaining_vulns_custom:
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
            
            # Create iteration 1 result by patching with all detected vulnerabilities
            iteration_1_result = self._step_patching(current_code, all_vulns)
            iteration_1_result['iteration_number'] = 1
            iteration_1_result['custom_detector_vulns'] = iteration_custom_vulns
            iteration_1_result['bandit_analysis'] = bandit_result
            iteration_1_result['semgrep_analysis'] = semgrep_result
            all_iterations.append(iteration_1_result)
            current_code = iteration_1_result['patched_code']
            
            # Continue with subsequent iterations (2 to max)
            for iteration_count in range(2, self.max_patch_iterations + 1):
                # Re-run static analysis on current patched code
                bandit_final = self._step_static_analysis_bandit(current_code)
                secondary_final = self._step_static_analysis_secondary(current_code)
                
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

                # Accumulate all found in this iteration (for iteration-only count)
                iteration_findings.extend(remaining_vulns)
                iteration_findings.extend(bandit_vulns)
                iteration_findings.extend(semgrep_vulns)
                
                # Accumulate all found in this iteration (for total count with initial)
                all_found_vulns.extend(remaining_vulns)
                all_found_vulns.extend(bandit_vulns)
                all_found_vulns.extend(semgrep_vulns)
                
                # Track per-tool counts for iterations
                iteration_custom_count += len(remaining_vulns)
                iteration_bandit_count += len(bandit_vulns)
                iteration_semgrep_count += len(semgrep_vulns)
                
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
                iteration_result['iteration_number'] = iteration_count
                iteration_result['custom_detector_vulns'] = iteration_custom_vulns
                all_iterations.append(iteration_result)
                current_code = iteration_result['patched_code']
                
                # Store per-iteration static analysis results in the iteration result
                all_iterations[-1]['bandit_analysis'] = bandit_final
                all_iterations[-1]['semgrep_analysis'] = secondary_final
        
            # After iteration loop completes
            results['total_iterations'] = len(all_iterations)
            results['patch_iterations'] = all_iterations
            results['final_patched_code'] = current_code
        
        # Step 7: Final Static Analysis (use latest results from loop)
        print("\n🔬 Step 7: Recording final static analysis results...")
        results['bandit_final'] = bandit_final
        results['secondary_final'] = secondary_final
        
        # Step 8: Evaluation and Metrics
        print("\n📈 Step 8: Calculating metrics...")
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
        if all_iterations:
            total_remaining_vulns_raw = all_iterations[-1]['unpatched_vulns'] + bandit_final_vulns + semgrep_final_vulns
        else:
            # No iterations needed, check final code
            final_custom_vulns = self._detect_remaining_vulnerabilities(current_code)
            total_remaining_vulns_raw = final_custom_vulns + bandit_final_vulns + semgrep_final_vulns
        # Deduplicate remaining vulnerabilities by (CWE, line) for consistency
        total_remaining_vulns = self._deduplicate_vulns_by_line([total_remaining_vulns_raw])

        # NOTE: Do NOT add final bandit/semgrep findings to all_found_vulns again
        # They are already included from iterations or initial findings
        # all_found_vulns already contains complete totals
        
        # Calculate iterations-only findings (excluding initial code)
        # Deduplicate iteration findings by (CWE + line) - vulnerabilities found during patch iterations only
        iterations_only_deduped = self._deduplicate_vulns_by_line([iteration_findings])
        results['all_iterations_deduped_count'] = len(iterations_only_deduped)
        results['all_iterations_deduped'] = iterations_only_deduped
        print(f"📊 DEBUG Iterations Only Deduped Count: {len(iterations_only_deduped)} (total before dedup: {len(iteration_findings)})")
        
        # Calculate all findings (initial + iterations) for total detected metric
        all_findings_deduped = self._deduplicate_vulns_by_line([all_found_vulns])
        print(f"📊 DEBUG All Findings Deduped Count: {len(all_findings_deduped)} (total before dedup: {len(all_found_vulns)})")
        
        # Keep unique_found_vulns for backward compatibility with other code
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
        # Raw counts (no dedup) for display
        results['total_vulns_found_all_occurrences'] = len(all_found_vulns)
        results['total_iterations_all_occurrences'] = len(iteration_findings)
        
        # Store per-tool counts for both initial and iterations
        results['iteration_custom_count'] = iteration_custom_count
        results['iteration_bandit_count'] = iteration_bandit_count
        results['iteration_semgrep_count'] = iteration_semgrep_count
        
        # Overall totals per tool (initial + iterations)
        results['total_custom_count'] = initial_custom_count + iteration_custom_count
        results['total_bandit_count'] = initial_bandit_count + iteration_bandit_count
        results['total_semgrep_count'] = initial_semgrep_count + iteration_semgrep_count
        # For UI: show total found and fixed
        # Vulnerabilities fixed = total unique found - remaining unique in final code
        results['total_vulns_found'] = len(unique_found_vulns)
        results['total_vulns_remaining'] = len(total_remaining_vulns)
        results['total_vulns_fixed'] = max(0, len(unique_found_vulns) - len(total_remaining_vulns))
        
        # Aggregate Bandit issues across original + all iterations
        all_bandit_issues = list(bandit_original.get('issues', [])) if bandit_original.get('success') else []
        all_semgrep_issues = list(semgrep_original.get('issues', [])) if semgrep_original.get('success') else []
        
        for iteration in all_iterations:
            bandit_analysis = iteration.get('bandit_analysis', {})
            semgrep_analysis = iteration.get('semgrep_analysis', {})
            
            if bandit_analysis.get('success'):
                all_bandit_issues.extend(bandit_analysis.get('issues', []))
            
            if semgrep_analysis.get('success'):
                all_semgrep_issues.extend(semgrep_analysis.get('issues', []))
        
        # Create aggregated tool results for comparison
        bandit_aggregated = {
            'success': True,
            'issues': all_bandit_issues
        }
        semgrep_aggregated = {
            'success': True,
            'issues': all_semgrep_issues
        }
        
        # Unique vulnerability count must be by CWE ID across all stages/tools
        # Normalize CWE IDs to consistent format (3 digits with leading zeros, no descriptions)
        unique_cwe_ids = set()
        for v in all_found_vulns:
            cwe_id = v.get('cwe_id')
            if cwe_id is not None and cwe_id != '':
                # Convert to string and extract just the numeric part
                cwe_str = str(cwe_id)
                # Remove any text after colon (e.g., "89: SQL Injection" -> "89")
                if ':' in cwe_str:
                    cwe_str = cwe_str.split(':')[0].strip()
                # Remove 'CWE-' prefix if present
                if cwe_str.upper().startswith('CWE-'):
                    cwe_str = cwe_str[4:]
                # Extract only digits
                cwe_str = ''.join(filter(str.isdigit, cwe_str))
                # Pad to 3 digits
                if cwe_str:
                    cwe_str = cwe_str.zfill(3)
                    unique_cwe_ids.add(cwe_str)
        
        # Calculate remaining unique CWE IDs with same normalization
        remaining_cwe_ids = set()
        for v in total_remaining_vulns:
            cwe_id = v.get('cwe_id')
            if cwe_id is not None and cwe_id != '':
                # Apply same normalization
                cwe_str = str(cwe_id)
                if ':' in cwe_str:
                    cwe_str = cwe_str.split(':')[0].strip()
                if cwe_str.upper().startswith('CWE-'):
                    cwe_str = cwe_str[4:]
                cwe_str = ''.join(filter(str.isdigit, cwe_str))
                if cwe_str:
                    cwe_str = cwe_str.zfill(3)
                    remaining_cwe_ids.add(cwe_str)
        
        # Total fixed = raw occurrences found - raw occurrences remaining (no filters)
        total_remaining_occurrences = len(total_remaining_vulns)
        total_fixed_occurrences = len(all_found_vulns) - total_remaining_occurrences
        
        metrics = self._step_calculate_metrics(
            all_findings_deduped,  # Use all findings (initial + iterations) deduplicated by line only
            total_remaining_vulns,
            bandit_aggregated,
            semgrep_aggregated,
            results.get('initial_code_deduped_count', 0),
            results.get('all_iterations_deduped_count', 0)
        )
        
        # Unique vulnerability metrics (by CWE ID only)
        metrics['total_detected'] = len(unique_cwe_ids)
        metrics['unique_cwe_ids'] = sorted(list(unique_cwe_ids))
        metrics['total_remaining'] = len(remaining_cwe_ids)
        metrics['remaining_cwe_ids'] = sorted(list(remaining_cwe_ids))
        
        # Override total_fixed with raw occurrence count (not deduplicated)
        metrics['total_fixed'] = total_fixed_occurrences
        
        # Override severity breakdowns to use all_found_vulns (raw occurrences) instead of deduplicated
        severity_before_all = self.metrics_calc.generate_severity_breakdown(all_found_vulns)
        severity_after_all = self.metrics_calc.generate_severity_breakdown(total_remaining_vulns)
        metrics['severity_before_patch'] = severity_before_all
        metrics['severity_after_patch'] = severity_after_all
        
        # Add raw occurrence counts (no deduplication) for UI
        metrics['total_detected_all_occurrences'] = len(all_found_vulns)
        metrics['total_remaining_all_occurrences'] = total_remaining_occurrences
        metrics['iterations_total_all_occurrences'] = len(iteration_findings)
        # Per-tool raw totals (all occurrences, no dedup) - sum of initial + iterations for each tool
        metrics['custom_detector_total_all_occurrences'] = initial_custom_count + iteration_custom_count
        metrics['bandit_total_all_occurrences'] = initial_bandit_count + iteration_bandit_count
        metrics['semgrep_total_all_occurrences'] = initial_semgrep_count + iteration_semgrep_count
        print(f"📊 DEBUG Metrics Before Setting:")
        print(f"   initial_code_deduped_count from results: {results.get('initial_code_deduped_count')}")
        print(f"   all_iterations_deduped_count from results: {results.get('all_iterations_deduped_count')}")
        print(f"📊 DEBUG Metrics After Calculate:")
        print(f"   initial_code_deduped_count in metrics: {metrics.get('initial_code_deduped_count')}")
        print(f"   all_iterations_deduped_count in metrics: {metrics.get('all_iterations_deduped_count')}")
        print(f"   total_detected (unique CWE count): {metrics.get('total_detected')}")
        print(f"   unique_cwe_ids: {metrics.get('unique_cwe_ids')}")
        print(f"   total_remaining (unique remaining CWEs): {metrics.get('total_remaining')}")
        print(f"   remaining_cwe_ids: {metrics.get('remaining_cwe_ids')}")
        print(f"   total_fixed (unique CWEs fixed): {metrics.get('total_fixed')}")
        print(f"   total_detected_all_occurrences: {metrics.get('total_detected_all_occurrences')}")
        # Tool-wise detected counts across all iterations (deduped)
        bandit_detected = len([v for v in unique_found_vulns if v.get('detection_method') == 'bandit'])
        semgrep_detected = len([v for v in unique_found_vulns if v.get('detection_method') == 'semgrep'])
        metrics['bandit_initial'] = bandit_detected
        metrics['semgrep_initial'] = semgrep_detected
        results['metrics'] = metrics
        
        # Step 9: Final Reporting
        print("\n📄 Step 9: Generating final reports...")
        final_reports = self._step_final_reporting(
            results,
            workflow_id
        )
        results['final_reports'] = final_reports
        
        # Determine overall status based on all tools (custom + Bandit + Semgrep)
        if len(total_remaining_vulns) == 0:
            results['status'] = 'fully_patched'
            results['show_patch_info_message'] = False
            print("\n✅ Workflow completed successfully - all vulnerabilities patched!")
        else:
            results['status'] = 'partially_patched'
            results['show_patch_info_message'] = True
            print(f"\n⚠️  Workflow completed - {len(total_remaining_vulns)} vulnerabilities remain")
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
    
    def _deduplicate_vulns_by_line(self, vuln_lists: List[List[Dict]]) -> List[Dict]:
        """
        Deduplicate vulnerabilities by CWE ID and line number only.
        If the same CWE appears on different lines, count them separately.
        If the same CWE appears on the same line but detected by different tools, count as 1.
        
        Args:
            vuln_lists: List of vulnerability lists to merge and deduplicate
            
        Returns:
            Deduplicated list of vulnerabilities
        """
        # Flatten all vulnerability lists
        all_vulns = []
        for vuln_list in vuln_lists:
            if vuln_list:
                all_vulns.extend(vuln_list)
        
        print(f"      Dedup input: {len(all_vulns)} total items before dedup")
        
        # Deduplicate by (CWE ID, line number) - same CWE on same line counts as 1
        seen_keys = set()
        deduped = []
        
        for vuln in all_vulns:
            cwe_id = vuln.get('cwe_id', 'Unknown')
            # Try 'line' first, then 'line_number', handle falsy values properly
            line_num = vuln.get('line')
            if line_num is None:
                line_num = vuln.get('line_number', 'Unknown')
            
            key = (cwe_id, line_num)
            
            if key not in seen_keys:
                seen_keys.add(key)
                deduped.append(vuln)
        
        return deduped
    
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
            
            # Use CWE ID from Bandit (available in 1.7.5+)
            cwe_id = issue.get('cwe_id', '1035')  # Default to CWE-1035 if not provided
            
            vuln = {
                'cwe_id': cwe_id,
                'cwe_name': issue.get('test_name', 'Unknown'),
                'severity': issue.get('severity', 'MEDIUM').upper(),
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
            
            # Use CWE ID from Semgrep metadata (available in recent versions)
            cwe_id = issue.get('cwe_id', '1035')  # Default to CWE-1035 if not provided
            
            vuln = {
                'cwe_id': cwe_id,
                'cwe_name': self.detector._get_cwe_name(cwe_id) if cwe_id else 'Unknown',
                'severity': issue.get('severity', 'MEDIUM').upper(),
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
    
    def _step_calculate_metrics(
        self,
        original_vulns: List[Dict],
        remaining_vulns: List[Dict],
        bandit_results: Dict,
        secondary_results: Dict,
        initial_code_deduped_count: int = 0,
        all_iterations_deduped_count: int = 0
    ) -> Dict:
        """Step 10: Calculate comprehensive metrics."""
        return self.metrics_calc.calculate_comprehensive_metrics(
            original_vulns,
            remaining_vulns,
            bandit_results,
            secondary_results,
            initial_code_deduped_count,
            all_iterations_deduped_count
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
        
        # Patch report (only if at least one iteration exists)
        if results.get('patch_iterations'):
            last_patch = results['patch_iterations'][-1]
            reports['patch_report'] = self.reporter.export_patch_report(
                results['cleaned_code'],
                results['final_patched_code'],
                last_patch.get('changes', ''),
                last_patch.get('unpatched_vulns', []),
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
