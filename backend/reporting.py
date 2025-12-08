"""
Reporting module: Generates comprehensive tables, CSV, and JSON reports for vulnerabilities.
"""
import csv
import json
import os
from datetime import datetime
from typing import List, Dict


class VulnerabilityReporter:
    """
    Generate comprehensive reports for detected vulnerabilities, patches, and analysis results.
    """
    
    def __init__(self, output_dir: str = "reports"):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
    
    def export_vulnerability_report(
        self,
        vulnerabilities: List[Dict],
        filename_base: str = None
    ) -> Dict[str, str]:
        """
        Export vulnerabilities to CSV and JSON formats.
        
        Returns:
            Dict with paths to generated files
        """
        if not vulnerabilities:
            return {
                'csv_path': None,
                'json_path': None,
                'message': 'No vulnerabilities to report'
            }
        
        # Generate filename with timestamp if not provided
        if not filename_base:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename_base = f"vulnerability_report_{timestamp}"
        
        csv_path = os.path.join(self.output_dir, f"{filename_base}.csv")
        json_path = os.path.join(self.output_dir, f"{filename_base}.json")
        
        # Export to CSV
        if vulnerabilities:
            # Flatten nested dictionaries for CSV
            flat_vulns = self._flatten_vulnerabilities(vulnerabilities)
            
            with open(csv_path, 'w', newline='', encoding='utf-8') as csvfile:
                fieldnames = flat_vulns[0].keys()
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(flat_vulns)
        
        # Export to JSON (with full structure)
        with open(json_path, 'w', encoding='utf-8') as jsonfile:
            json.dump(vulnerabilities, jsonfile, indent=2, ensure_ascii=False)
        
        return {
            'csv_path': csv_path,
            'json_path': json_path,
            'count': len(vulnerabilities)
        }
    
    def _flatten_vulnerabilities(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """Flatten vulnerability dictionaries for CSV export."""
        flattened = []
        
        for vuln in vulnerabilities:
            flat_vuln = {
                'cwe_id': vuln.get('cwe_id', ''),
                'cwe_name': vuln.get('cwe_name', ''),
                'severity': vuln.get('severity', ''),
                'line_number': vuln.get('line_number', ''),
                'description': vuln.get('description', ''),
                'confidence': vuln.get('confidence', ''),
                'detection_method': vuln.get('detection_method', ''),
                'remediation_priority': vuln.get('remediation_priority', ''),
                'code_snippet': vuln.get('code_snippet', '').replace('\n', ' | '),
                'explanation': vuln.get('explanation', ''),
                'patch_note': vuln.get('patch_note', '')
            }
            flattened.append(flat_vuln)
        
        return flattened
    
    def export_patch_report(
        self,
        original_code: str,
        patched_code: str,
        changes: List[Dict],
        unpatched_vulns: List[Dict],
        filename_base: str = None
    ) -> Dict[str, str]:
        """
        Export patch information including before/after code and changes.
        """
        if not filename_base:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename_base = f"patch_report_{timestamp}"
        
        report_path = os.path.join(self.output_dir, f"{filename_base}.json")
        diff_path = os.path.join(self.output_dir, f"{filename_base}_diff.txt")
        
        # Generate diff
        diff_text = self._generate_diff(original_code, patched_code)
        
        # Create comprehensive report
        report = {
            'timestamp': datetime.now().isoformat(),
            'original_code': original_code,
            'patched_code': patched_code,
            'changes_applied': changes,
            'unpatched_vulnerabilities': unpatched_vulns,
            'patch_success_rate': len(changes) / (len(changes) + len(unpatched_vulns)) if (len(changes) + len(unpatched_vulns)) > 0 else 0.0
        }
        
        # Export report
        with open(report_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        # Export diff
        with open(diff_path, 'w', encoding='utf-8') as f:
            f.write(diff_text)
        
        return {
            'report_path': report_path,
            'diff_path': diff_path,
            'changes_count': len(changes),
            'unpatched_count': len(unpatched_vulns)
        }
    
    def export_iteration_codes(
        self,
        patch_iterations: List[Dict],
        filename_base: str = None
    ) -> Dict[str, str]:
        """
        Export patched code from each iteration to separate files.
        
        Args:
            patch_iterations: List of patch iteration results from workflow
            filename_base: Base filename for exports
            
        Returns:
            Dict with paths to saved iteration code files
        """
        if not filename_base:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename_base = f"patch_iterations_{timestamp}"
        
        iteration_files = {}
        
        for idx, iteration in enumerate(patch_iterations, 1):
            if 'patched_code' in iteration:
                code_file = os.path.join(
                    self.output_dir,
                    f"{filename_base}_iteration_{idx}.py"
                )
                
                with open(code_file, 'w', encoding='utf-8') as f:
                    f.write(iteration['patched_code'])
                
                iteration_files[f'iteration_{idx}'] = code_file
        
        return iteration_files
    
    def _generate_diff(self, original: str, patched: str) -> str:
        """Generate unified diff between original and patched code."""
        import difflib
        
        diff = difflib.unified_diff(
            original.splitlines(keepends=True),
            patched.splitlines(keepends=True),
            fromfile='original.py',
            tofile='patched.py',
            lineterm=''
        )
        
        return ''.join(diff)
    
    def export_static_analysis_report(
        self,
        bandit_results: Dict,
        secondary_results: Dict,
        comparison_metrics: Dict,
        filename_base: str = None
    ) -> str:
        """
        Export static analysis results from multiple tools.
        """
        if not filename_base:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename_base = f"static_analysis_{timestamp}"
        
        report_path = os.path.join(self.output_dir, f"{filename_base}.json")
        
        report = {
            'timestamp': datetime.now().isoformat(),
            'bandit_analysis': {
                'success': bandit_results.get('success', False),
                'issues': bandit_results.get('issues', []),
                'summary': bandit_results.get('summary', {})
            },
            'secondary_tool_analysis': {
                'success': secondary_results.get('success', False),
                'issues': secondary_results.get('issues', []),
                'summary': secondary_results.get('summary', {})
            },
            'comparison': comparison_metrics
        }
        
        with open(report_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        return report_path
    
    def export_metrics_report(
        self,
        metrics: Dict,
        filename_base: str = None
    ) -> str:
        """
        Export comprehensive metrics report as HTML with visual charts.
        """
        if not filename_base:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename_base = f"metrics_report_{timestamp}"
        
        report_path = os.path.join(self.output_dir, f"{filename_base}.html")
        
        # Extract metrics data
        pe = metrics.get('patching_effectiveness', {})
        tc = metrics.get('tool_comparison', {})
        severity_before = metrics.get('severity_before_patch', {})
        severity_after = metrics.get('severity_after_patch', {})
        
        # Generate HTML with charts
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Metrics Report</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        h1 {{ color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }}
        h2 {{ color: #34495e; margin-top: 30px; }}
        .chart-container {{ margin: 30px 0; padding: 20px; background: #fafafa; border-radius: 8px; }}
        .metric-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin: 20px 0; }}
        .metric-card {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 10px; text-align: center; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }}
        .metric-card h3 {{ margin: 0 0 10px 0; font-size: 14px; opacity: 0.9; }}
        .metric-card .value {{ font-size: 36px; font-weight: bold; margin: 10px 0; }}
        .metric-card.success {{ background: linear-gradient(135deg, #11998e 0%, #38ef7d 100%); }}
        .metric-card.warning {{ background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%); }}
        .metric-card.info {{ background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%); }}
        canvas {{ max-height: 400px; }}
        .timestamp {{ color: #7f8c8d; font-size: 14px; margin-top: 10px; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>📊 Vulnerability Analysis Metrics</h1>
        <p class="timestamp">Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
        
        <h2>Key Performance Indicators</h2>
        <p style="color: #7f8c8d; font-size: 14px; margin-bottom: 20px;">
            <strong>Note:</strong> Metrics combine results from Custom Detector, Bandit, and Semgrep.<br>
            <strong>Fix Rate vs Effectiveness:</strong> Fix Rate shows the percentage of vulnerabilities fixed. 
            Effectiveness Score adjusts this by penalizing if new vulnerabilities were introduced during patching 
            (reduces by 10% per new vulnerability). When both rates are equal, no new issues were introduced.
        </p>
        <div class="metric-grid">
            <div class="metric-card success">
                <h3>Total Vulnerabilities Detected</h3>
                <div class="value">{metrics.get('total_detected_all_occurrences', 0)}</div>
                <p>All Occurrences Found</p>
            </div>
            <div class="metric-card">
                <h3>Total Remaining</h3>
                <div class="value">{metrics.get('total_remaining_all_occurrences', 0)}</div>
                <p>All Tools Combined</p>
            </div>
            <div class="metric-card success">
                <h3>Total Fixed</h3>
                <div class="value">{metrics.get('total_fixed', 0)}</div>
                <p>Issues Resolved</p>
            </div>
            <div class="metric-card info">
                <h3>Fix Rate</h3>
                <div class="value">{pe.get('fix_rate', 0):.1%}</div>
                <p>Overall Effectiveness</p>
            </div>
        </div>
        
        <h2>Tool Breakdown</h2>
        <div class="metric-grid">
            <div class="metric-card">
                <h3>Custom Detector</h3>
                <div class="value">{metrics.get('custom_detector_total_all_occurrences', 0)}</div>
                <p>Total Custom Detector Found</p>
            </div>
            <div class="metric-card">
                <h3>Bandit</h3>
                <div class="value">{metrics.get('bandit_total_all_occurrences', 0)}</div>
                <p>Total Bandit Found</p>
            </div>
            <div class="metric-card">
                <h3>Semgrep</h3>
                <div class="value">{metrics.get('semgrep_total_all_occurrences', 0)}</div>
                <p>Total Semgrep Found</p>
            </div>
            <div class="metric-card info">
                <h3>Effectiveness</h3>
                <div class="value">{pe.get('effectiveness_score', 0):.1%}</div>
                <p>Quality Score</p>
            </div>
        </div>
        
        <h2>Severity Distribution</h2>
        <p style="color: #7f8c8d; margin: 10px 0 20px 0; font-size: 14px;">
            <strong>Total Detected:</strong> All vulnerabilities found across all phases (initial + iterations)<br>
            <strong>Remaining Unfixed:</strong> Vulnerabilities still present after all patching attempts (shows 0 if code is fully patched)
        </p>
        <div class="chart-container">
            <canvas id="severityChart"></canvas>
        </div>
        
        <h2>Tool Detection Comparison</h2>
        <div class="chart-container">
            <canvas id="toolChart"></canvas>
        </div>
        
        <h2>Patching Effectiveness Breakdown</h2>
        <div class="chart-container">
            <canvas id="patchingChart"></canvas>
        </div>
    </div>
    
    <script>
        // Severity Distribution Chart
        const severityCtx = document.getElementById('severityChart').getContext('2d');
        new Chart(severityCtx, {{
            type: 'bar',
            data: {{
                labels: ['Total Detected', 'Remaining Unfixed'],
                datasets: [{{
                    label: 'High Severity',
                    data: [
                        {metrics.get('severity_before_patch', {}).get('HIGH', 0)},
                        {metrics.get('severity_after_patch', {}).get('HIGH', 0)}
                    ],
                    backgroundColor: '#e74c3c'
                }}, {{
                    label: 'Medium Severity',
                    data: [
                        {metrics.get('severity_before_patch', {}).get('MEDIUM', 0)},
                        {metrics.get('severity_after_patch', {}).get('MEDIUM', 0)}
                    ],
                    backgroundColor: '#f39c12'
                }}, {{
                    label: 'Low Severity',
                    data: [
                        {metrics.get('severity_before_patch', {}).get('LOW', 0)},
                        {metrics.get('severity_after_patch', {}).get('LOW', 0)}
                    ],
                    backgroundColor: '#2ecc71'
                }}]
            }},
            options: {{
                responsive: true,
                plugins: {{
                    title: {{ display: true, text: 'Vulnerability Severity: All Detected vs. Remaining Unfixed' }},
                    legend: {{ position: 'top' }}
                }},
                scales: {{
                    y: {{ beginAtZero: true, title: {{ display: true, text: 'Count' }} }}
                }}
            }}
        }});
        
        // Tool Comparison Chart
        const toolCtx = document.getElementById('toolChart').getContext('2d');
        new Chart(toolCtx, {{
            type: 'doughnut',
            data: {{
                labels: ['Custom Detector', 'Bandit', 'Semgrep'],
                datasets: [{{
                    data: [
                        {metrics.get('custom_detector_total_all_occurrences', 0)},
                        {metrics.get('bandit_total_all_occurrences', 0)},
                        {metrics.get('semgrep_total_all_occurrences', 0)}
                    ],
                    backgroundColor: ['#3498db', '#9b59b6', '#e67e22']
                }}]
            }},
            options: {{
                responsive: true,
                plugins: {{
                    title: {{ display: true, text: 'Vulnerabilities Detected by Each Tool (All Phases)' }},
                    legend: {{ position: 'right' }}
                }}
            }}
        }});
        
        // Patching Effectiveness Chart
        const patchCtx = document.getElementById('patchingChart').getContext('2d');
        new Chart(patchCtx, {{
            type: 'pie',
            data: {{
                labels: ['Fixed', 'Remaining'],
                datasets: [{{
                    data: [
                        {metrics.get('total_fixed', 0)},
                        {metrics.get('total_remaining_all_occurrences', 0)}
                    ],
                    backgroundColor: ['#27ae60', '#e74c3c']
                }}]
            }},
            options: {{
                responsive: true,
                plugins: {{
                    title: {{ display: true, text: 'Vulnerabilities Fixed vs Remaining' }},
                    legend: {{ position: 'bottom' }}
                }}
            }}
        }});
    </script>
</body>
</html>
"""
        
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return report_path
    

    def generate_html_summary(
        self,
        vulnerabilities: List[Dict],
        patch_info: Dict,
        metrics: Dict,
        original_code: str = "",
        patched_code: str = ""
    ) -> str:
        """
        Generate an HTML summary report with custom executive summary and detected vulnerabilities table as per requirements.
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        html_path = os.path.join(self.output_dir, f"summary_report_{timestamp}.html")

        # Gather tool counts for initial and iteration (from metrics)
        init_custom = metrics.get('initial_custom_count', 0)
        init_bandit = metrics.get('initial_bandit_count', 0)
        init_semgrep = metrics.get('initial_semgrep_count', 0)
        iter_custom = metrics.get('custom_detector_total_all_occurrences', 0)
        iter_bandit = metrics.get('bandit_total_all_occurrences', 0)
        iter_semgrep = metrics.get('semgrep_total_all_occurrences', 0)
        total_all = iter_custom + iter_bandit + iter_semgrep

        # Gather all vulnerabilities from all tools, initial and iteration
        all_vulns = metrics.get('all_found_vulns_occurrences', [])
        # If not present, fallback to vulnerabilities param
        if not all_vulns:
            all_vulns = vulnerabilities

        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Vulnerability Analysis Report</title>
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1400px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        h1 {{ color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }}
        h2 {{ color: #34495e; margin-top: 30px; border-bottom: 2px solid #ecf0f1; padding-bottom: 5px; }}
        table {{ border-collapse: collapse; width: 100%; margin-bottom: 20px; background: white; }}
        th, td {{ border: 1px solid #ddd; padding: 12px; text-align: left; }}
        th {{ background-color: #3498db; color: white; font-weight: 600; }}
        tr:nth-child(even) {{ background-color: #f8f9fa; }}
        tr:hover {{ background-color: #e8f4f8; }}
        .high {{ color: #e74c3c; font-weight: bold; }}
        .medium {{ color: #f39c12; font-weight: bold; }}
        .low {{ color: #27ae60; font-weight: bold; }}
        .summary-flex {{ display: flex; justify-content: space-between; gap: 40px; margin-bottom: 20px; }}
        .summary-col {{ flex: 1; background: #f3f6fa; border-radius: 10px; padding: 20px; }}
        .summary-col h3 {{ margin-top: 0; color: #2c3e50; font-size: 18px; }}
        .summary-total {{ text-align: center; margin: 20px 0; font-size: 20px; font-weight: bold; color: #764ba2; }}
        .metric {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; margin: 15px 0; border-radius: 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }}
        .metric p {{ margin: 8px 0; font-size: 16px; }}
        .metric strong {{ font-weight: 600; }}
        .code-section {{ margin: 20px 0; }}
        .code-container {{ display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-top: 15px; }}
        .code-box {{ background: #2d2d2d; color: #f8f8f2; padding: 20px; border-radius: 8px; overflow-x: auto; }}
        .code-box h3 {{ color: #f8f8f2; margin-top: 0; padding-bottom: 10px; border-bottom: 2px solid #555; }}
        .code-box pre {{ margin: 0; font-family: 'Consolas', 'Monaco', 'Courier New', monospace; font-size: 13px; line-height: 1.6; white-space: pre-wrap; word-wrap: break-word; }}
        .severity-dist {{ display: flex; gap: 15px; margin: 20px 0; }}
        .severity-card {{ flex: 1; padding: 15px; border-radius: 8px; text-align: center; color: white; }}
        .severity-card.high {{ background: #e74c3c; }}
        .severity-card.medium {{ background: #f39c12; }}
        .severity-card.low {{ background: #27ae60; }}
        .severity-card .count {{ font-size: 32px; font-weight: bold; }}
        .severity-card .label {{ font-size: 14px; opacity: 0.9; margin-top: 5px; }}
        .timestamp {{ color: #7f8c8d; font-size: 14px; }}
        .success-badge {{ background: #27ae60; color: white; padding: 5px 15px; border-radius: 20px; display: inline-block; font-weight: bold; }}
        .warning-badge {{ background: #f39c12; color: white; padding: 5px 15px; border-radius: 20px; display: inline-block; font-weight: bold; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔒 LLM Code Vulnerability Analysis Report</h1>
        <p class="timestamp">Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>

        <h2>Executive Summary</h2>
        <div class="summary-flex">
            <div class="summary-col">
                <h3>Iteration Process</h3>
                <p>Total vulnerabilities custom detector found: <strong>{iter_custom}</strong></p>
                <p>Total Bandit found: <strong>{iter_bandit}</strong></p>
                <p>Total Semgrep found: <strong>{iter_semgrep}</strong></p>
            </div>
            <div class="summary-col">
                <h3>Initial Process</h3>
                <p>Total vulnerabilities custom detector found: <strong>{init_custom}</strong></p>
                <p>Total Bandit found: <strong>{init_bandit}</strong></p>
                <p>Total Semgrep found: <strong>{init_semgrep}</strong></p>
            </div>
        </div>
        <div class="summary-total">
            Total found in all processes by all tools: <span style="color:#e67e22">{total_all}</span>
        </div>

        <h2>Detected Vulnerabilities</h2>
        <table>
            <tr>
                <th>CWE ID</th>
                <th>CWE Name</th>
                <th>Severity</th>
                <th>Line</th>
                <th>Description</th>
                <th>Detection Method</th>
            </tr>
            {''.join(self._generate_html_vuln_rows(all_vulns))}
        </table>

        <h2>Severity Distribution</h2>
        <div class="severity-dist">
            {self._generate_severity_cards(metrics.get('severity_before_patch', {}))}
        </div>

        <h2>Code Analysis</h2>
        <div class="code-section">
            <div class="code-container">
                <div class="code-box">
                    <h3>📝 Original Code (With Vulnerabilities)</h3>
                    <pre>{self._escape_html(original_code) if original_code else 'Code not available'}</pre>
                </div>
                <div class="code-box">
                    <h3>✅ Patched Code (Vulnerabilities Fixed)</h3>
                    <pre>{self._escape_html(patched_code) if patched_code else 'Code not available'}</pre>
                </div>
            </div>
        </div>

        <h2>Patching Details</h2>
        <p><strong>Patches Done:</strong> {patch_info.get('changes_count', 0)}</p>
        <p><strong>Patch Success Rate:</strong> {patch_info.get('changes_count', 0) / max(total_all, 1):.2%}</p>

        <div style="margin-top: 40px; padding-top: 20px; border-top: 2px solid #ecf0f1; color: #7f8c8d; font-size: 12px;">
            <p>Generated by LLM-CVAM Framework - Code Vulnerability Analysis and Mitigation System</p>
        </div>
    </div>
</body>
</html>
"""
        with open(html_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        return html_path
    
    def _escape_html(self, text: str) -> str:
        """Escape HTML special characters."""
        if not text:
            return ""
        return (text
                .replace('&', '&amp;')
                .replace('<', '&lt;')
                .replace('>', '&gt;')
                .replace('"', '&quot;')
                .replace("'", '&#39;'))
    
    def _generate_html_vuln_rows(self, vulnerabilities: List[Dict]) -> List[str]:
        """Generate HTML table rows for vulnerabilities."""
        rows = []
        for vuln in vulnerabilities:
            severity_class = vuln.get('severity', 'LOW').lower()
            row = f"""
        <tr>
            <td>{vuln.get('cwe_id', 'N/A')}</td>
            <td>{vuln.get('cwe_name', 'N/A')}</td>
            <td class="{severity_class}">{vuln.get('severity', 'N/A')}</td>
            <td>{vuln.get('line_number', 'N/A')}</td>
            <td>{vuln.get('description', 'N/A')}</td>
        </tr>
"""
            rows.append(row)
        return rows
    
    def _generate_severity_html(self, severity_breakdown: Dict) -> str:
        """Generate HTML for severity breakdown."""
        html = "<ul>"
        for severity, count in severity_breakdown.items():
            if count > 0:
                html += f"<li><strong>{severity}:</strong> {count}</li>"
        html += "</ul>"
        return html
    
    def _generate_severity_cards(self, severity_breakdown: Dict) -> str:
        """Generate HTML cards for severity distribution."""
        cards = []
        severity_order = ['HIGH', 'MEDIUM', 'LOW']
        classes = {'HIGH': 'high', 'MEDIUM': 'medium', 'LOW': 'low'}
        
        for severity in severity_order:
            count = severity_breakdown.get(severity, 0)
            cards.append(f'''
            <div class="severity-card {classes.get(severity, '')}">
                <div class="count">{count}</div>
                <div class="label">{severity}</div>
            </div>
            ''')
        
        return ''.join(cards)


# Backwards compatibility function
def export_report(vulns, path_base):
    """Export vulnerabilities to CSV and JSON."""
    reporter = VulnerabilityReporter()
    
    if not vulns:
        return None, None
    
    result = reporter.export_vulnerability_report(vulns, os.path.basename(path_base))
    return result.get('csv_path'), result.get('json_path')
