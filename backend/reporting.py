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
        
        # Extract metrics data with safe defaults
        pe = metrics.get('patching_effectiveness', {})
        tc = metrics.get('tool_comparison', {})
        severity_before = metrics.get('severity_before_patch', {})
        severity_after = metrics.get('severity_after_patch', {})
        
        # Debug print to check data
        print(f"\n🔍 DEBUG - Metrics Report Data:")
        print(f"   severity_before_patch: {severity_before}")
        print(f"   severity_after_patch: {severity_after}")
        print(f"   custom_detector_total: {metrics.get('custom_detector_total_all_occurrences', 0)}")
        print(f"   bandit_total: {metrics.get('bandit_total_all_occurrences', 0)}")
        print(f"   semgrep_total: {metrics.get('semgrep_total_all_occurrences', 0)}")
        print(f"   total_fixed: {metrics.get('total_fixed', 0)}")
        print(f"   total_remaining: {metrics.get('total_remaining_all_occurrences', 0)}")
        
        # Extract severity counts with defaults
        sev_before_high = int(severity_before.get('HIGH', 0) or 0)
        sev_before_med = int(severity_before.get('MEDIUM', 0) or 0)
        sev_before_low = int(severity_before.get('LOW', 0) or 0)
        sev_after_high = int(severity_after.get('HIGH', 0) or 0)
        sev_after_med = int(severity_after.get('MEDIUM', 0) or 0)
        sev_after_low = int(severity_after.get('LOW', 0) or 0)
        
        custom_total = int(metrics.get('custom_detector_total_all_occurrences', 0) or 0)
        bandit_total = int(metrics.get('bandit_total_all_occurrences', 0) or 0)
        semgrep_total = int(metrics.get('semgrep_total_all_occurrences', 0) or 0)
        total_fixed = int(metrics.get('total_fixed', 0) or 0)
        total_remaining = int(metrics.get('total_remaining_all_occurrences', 0) or 0)
        
        timestamp_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        total_detected = int(metrics.get('total_detected_all_occurrences', 0) or 0)
        fix_rate = pe.get('fix_rate', 0) or 0
        effectiveness_score = pe.get('effectiveness_score', 0) or 0
        
        # Build HTML content
        html_content = """<!DOCTYPE html>
<html>
<head>
    <title>Metrics Report</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h1 { color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }
        h2 { color: #34495e; margin-top: 30px; }
        .chart-container { margin: 30px 0; padding: 20px; background: #fafafa; border-radius: 8px; position: relative; width: 100%; height: 400px; }
        .metric-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin: 20px 0; }
        .metric-card { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 10px; text-align: center; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
        .metric-card h3 { margin: 0 0 10px 0; font-size: 14px; opacity: 0.9; }
        .metric-card .value { font-size: 36px; font-weight: bold; margin: 10px 0; }
        .metric-card.success { background: linear-gradient(135deg, #11998e 0%, #38ef7d 100%); }
        .metric-card.warning { background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%); }
        .metric-card.info { background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%); }
        canvas { max-height: 350px !important; }
        .timestamp { color: #7f8c8d; font-size: 14px; margin-top: 10px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>📊 Vulnerability Analysis Metrics</h1>
        <p class="timestamp">Generated: """ + timestamp_str + """</p>
        
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
                <div class="value">""" + str(total_detected) + """</div>
                <p>All Occurrences Found</p>
            </div>
            <div class="metric-card">
                <h3>Total Remaining</h3>
                <div class="value">""" + str(total_remaining) + """</div>
                <p>All Tools Combined</p>
            </div>
            <div class="metric-card success">
                <h3>Total Fixed</h3>
                <div class="value">""" + str(total_fixed) + """</div>
                <p>Issues Resolved</p>
            </div>
            <div class="metric-card info">
                <h3>Fix Rate</h3>
                <div class="value">""" + f"{fix_rate:.1%}" + """</div>
                <p>Overall Effectiveness</p>
            </div>
        </div>
        
        <h2>Tool Breakdown</h2>
        <div class="metric-grid">
            <div class="metric-card">
                <h3>Custom Detector</h3>
                <div class="value">""" + str(custom_total) + """</div>
                <p>Total Custom Detector Found</p>
            </div>
            <div class="metric-card">
                <h3>Bandit</h3>
                <div class="value">""" + str(bandit_total) + """</div>
                <p>Total Bandit Found</p>
            </div>
            <div class="metric-card">
                <h3>Semgrep</h3>
                <div class="value">""" + str(semgrep_total) + """</div>
                <p>Total Semgrep Found</p>
            </div>
            <div class="metric-card info">
                <h3>Effectiveness</h3>
                <div class="value">""" + f"{effectiveness_score:.1%}" + """</div>
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
        console.log('Starting chart initialization...');
        
        // Severity Distribution Chart
        try {
            const severityCtx = document.getElementById('severityChart').getContext('2d');
            console.log('Severity chart data:', {
                high: [""" + str(sev_before_high) + """, """ + str(sev_after_high) + """],
                medium: [""" + str(sev_before_med) + """, """ + str(sev_after_med) + """],
                low: [""" + str(sev_before_low) + """, """ + str(sev_after_low) + """]
            });
            new Chart(severityCtx, {
                type: 'bar',
                data: {
                    labels: ['Total Detected', 'Remaining Unfixed'],
                    datasets: [
                        {
                            label: 'High Severity',
                            data: [""" + str(sev_before_high) + """, """ + str(sev_after_high) + """],
                            backgroundColor: '#e74c3c'
                        },
                        {
                            label: 'Medium Severity',
                            data: [""" + str(sev_before_med) + """, """ + str(sev_after_med) + """],
                            backgroundColor: '#f39c12'
                        },
                        {
                            label: 'Low Severity',
                            data: [""" + str(sev_before_low) + """, """ + str(sev_after_low) + """],
                            backgroundColor: '#2ecc71'
                        }
                    ]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        title: { display: true, text: 'Vulnerability Severity: All Detected vs. Remaining Unfixed' },
                        legend: { position: 'top' }
                    },
                    scales: {
                        y: { beginAtZero: true, title: { display: true, text: 'Count' } }
                    }
                }
            });
            console.log('Severity chart created successfully');
        } catch (e) {
            console.error('Severity chart error:', e);
        }
        
        // Tool Comparison Chart
        try {
            const toolCtx = document.getElementById('toolChart').getContext('2d');
            console.log('Tool chart data:', [""" + str(custom_total) + """, """ + str(bandit_total) + """, """ + str(semgrep_total) + """]);
            new Chart(toolCtx, {
                type: 'doughnut',
                data: {
                    labels: ['Custom Detector', 'Bandit', 'Semgrep'],
                    datasets: [{
                        data: [""" + str(custom_total) + """, """ + str(bandit_total) + """, """ + str(semgrep_total) + """],
                        backgroundColor: ['#3498db', '#9b59b6', '#e67e22']
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        title: { display: true, text: 'Vulnerabilities Detected by Each Tool (All Phases)' },
                        legend: { position: 'right' }
                    }
                }
            });
            console.log('Tool chart created successfully');
        } catch (e) {
            console.error('Tool chart error:', e);
        }
        
        // Patching Effectiveness Chart
        try {
            const patchCtx = document.getElementById('patchingChart').getContext('2d');
            console.log('Patch chart data:', [""" + str(total_fixed) + """, """ + str(total_remaining) + """]);
            new Chart(patchCtx, {
                type: 'pie',
                data: {
                    labels: ['Fixed', 'Remaining'],
                    datasets: [{
                        data: [""" + str(total_fixed) + """, """ + str(total_remaining) + """],
                        backgroundColor: ['#27ae60', '#e74c3c']
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        title: { display: true, text: 'Vulnerabilities Fixed vs Remaining' },
                        legend: { position: 'bottom' }
                    }
                }
            });
            console.log('Patch chart created successfully');
        } catch (e) {
            console.error('Patch chart error:', e);
        }
        
        console.log('All charts initialized');
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
        iter_custom = metrics.get('iteration_custom_count', 0)
        iter_bandit = metrics.get('iteration_bandit_count', 0)
        iter_semgrep = metrics.get('iteration_semgrep_count', 0)
        total_all = init_custom + init_bandit + init_semgrep + iter_custom + iter_bandit + iter_semgrep

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
            line_val = vuln.get('line_number') if vuln.get('line_number') is not None else vuln.get('line', 'N/A')
            detection = vuln.get('detection_method', vuln.get('source', 'N/A'))
            row = f"""
        <tr>
            <td>{vuln.get('cwe_id', 'N/A')}</td>
            <td>{vuln.get('cwe_name', 'N/A')}</td>
            <td class="{severity_class}">{vuln.get('severity', 'N/A')}</td>
            <td>{line_val}</td>
            <td>{vuln.get('description', 'N/A')}</td>
            <td>{detection}</td>
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
    
    def export_3way_overlap_evolution_report(self, results: Dict, output_dir: str = "test_reports") -> str:
        """
        Generate comprehensive HTML report showing 3-way tool agreement evolution across phases.
        
        Args:
            results: Complete workflow results with all_3way_comparisons
            output_dir: Directory to save the report
            
        Returns:
            Path to generated report file
        """
        import datetime
        
        os.makedirs(output_dir, exist_ok=True)
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = os.path.join(output_dir, f"3way_overlap_evolution_{timestamp}.html")
        
        # Extract 3-way comparison data
        all_comparisons = results.get('all_3way_comparisons', {})
        initial = all_comparisons.get('initial_code', {})
        iterations = all_comparisons.get('iterations', [])
        final = all_comparisons.get('final_code', {})
        
        # Helper function to extract data safely
        def get_comparison_data(comparison):
            # Always use len() for overlap keys, as they are lists/sets; fallback to int if needed
            def count(val):
                if isinstance(val, (list, set)):
                    return len(val)
                elif isinstance(val, int):
                    return val
                return 0

            def safe_list(val):
                if isinstance(val, (list, set, tuple)):
                    return list(val)
                return []
            return {
                'custom_only': count(comparison.get('custom_only_cwes', [])),
                'bandit_only': count(comparison.get('bandit_only_cwes', [])),
                'semgrep_only': count(comparison.get('secondary_only_cwes', [])),
                'custom_bandit': count(comparison.get('custom_bandit_overlap_cwes', [])),
                'custom_semgrep': count(comparison.get('custom_secondary_overlap_cwes', [])),
                'bandit_semgrep': count(comparison.get('bandit_secondary_overlap_cwes', [])),
                'three_way': count(comparison.get('three_way_overlap_cwes', [])),
                # Use *_overlap_cwes_list for detailed table
                'custom_bandit_list': comparison.get('custom_bandit_overlap_cwes_list', []),
                'custom_semgrep_list': comparison.get('custom_secondary_overlap_cwes_list', []),
                'bandit_semgrep_list': comparison.get('bandit_secondary_overlap_cwes_list', []),
                'three_way_list': comparison.get('three_way_overlap_cwes_list', []),
                'custom_total': comparison.get('custom_total', 0),
                'bandit_total': comparison.get('bandit_total', 0),
                'semgrep_total': comparison.get('secondary_total', 0)
            }
        
        # Build phase data
        phases = []
        
        # Initial phase
        if initial:
            phases.append({
                'name': 'Initial Code',
                'label': 'Initial',
                'data': get_comparison_data(initial)
            })
        
        # Iteration phases
        for i, iter_comp in enumerate(iterations, 1):
            if iter_comp:
                phases.append({
                    'name': f'After Iteration {i}',
                    'label': f'Iter {i}',
                    'data': get_comparison_data(iter_comp)
                })
        
        # Final phase
        if final:
            phases.append({
                'name': 'Final Code',
                'label': 'Final',
                'data': get_comparison_data(final)
            })
        
        # Prepare chart data
        phase_labels = [p['label'] for p in phases]
        three_way_data = [p['data']['three_way'] for p in phases]
        custom_bandit_data = [p['data']['custom_bandit'] for p in phases]
        custom_semgrep_data = [p['data']['custom_semgrep'] for p in phases]
        bandit_semgrep_data = [p['data']['bandit_semgrep'] for p in phases]
        
        custom_total_data = [p['data']['custom_total'] for p in phases]
        bandit_total_data = [p['data']['bandit_total'] for p in phases]
        semgrep_total_data = [p['data']['semgrep_total'] for p in phases]
        
        # Debug output
        print(f"\n📊 Debug: 3-Way Overlap Evolution Report Data")
        print(f"   Phases: {phase_labels}")
        print(f"   3-Way data: {three_way_data}")
        print(f"   Custom-Bandit data: {custom_bandit_data}")
        print(f"   Custom-Semgrep data: {custom_semgrep_data}")
        print(f"   Bandit-Semgrep data: {bandit_semgrep_data}")
        
        # Generate HTML
        html_content = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>3-Way Tool Overlap Evolution Report</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0"></script>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 20px;
            background-color: #f5f5f5;
        }
        .container {
            max-width: 1400px;
            margin: 0 auto;
            background-color: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        h1 {
            color: #2c3e50;
            border-bottom: 3px solid #3498db;
            padding-bottom: 10px;
        }
        h2 {
            color: #34495e;
            margin-top: 30px;
        }
        .chart-container {
            position: relative;
            height: 400px;
            margin: 30px 0;
        }
        .phase-table {
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }
        .phase-table th, .phase-table td {
            border: 1px solid #ddd;
            padding: 12px;
            text-align: center;
        }
        .phase-table th {
            background-color: #3498db;
            color: white;
            font-weight: bold;
        }
        .phase-table tr:nth-child(even) {
            background-color: #f9f9f9;
        }
        .highlight-3way {
            background-color: #e8f8f5;
            font-weight: bold;
        }
        .legend {
            margin: 20px 0;
            padding: 15px;
            background-color: #ecf0f1;
            border-radius: 5px;
        }
        .legend-item {
            display: inline-block;
            margin-right: 20px;
            margin-bottom: 10px;
        }
        .legend-color {
            display: inline-block;
            width: 20px;
            height: 20px;
            margin-right: 5px;
            vertical-align: middle;
        }
        .summary-box {
            background-color: #e8f8f5;
            border-left: 4px solid #1abc9c;
            padding: 15px;
            margin: 20px 0;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>📊 3-Way Tool Overlap Evolution Report</h1>
        <p><strong>Generated:</strong> """ + datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + """</p>
        
        <div class="summary-box">
            <h3>Report Purpose</h3>
            <p>This report tracks how vulnerability detection agreement between the three tools (Custom Detector, Bandit, Semgrep) 
            evolves across different phases of analysis. As code is patched, line numbers and vulnerability counts change, 
            which affects tool agreement.</p>
        </div>
        
        <h2>Evolution of Tool Agreement</h2>
        <div class="chart-container">
            <canvas id="overlapEvolutionChart"></canvas>
        </div>
        
        <h2>Total Vulnerabilities Detected Per Phase</h2>
        <div class="chart-container">
            <canvas id="totalVulnsChart"></canvas>
        </div>
        
        <h2>Detailed Phase-by-Phase Breakdown</h2>
        <table class="phase-table">
            <thead>
                <tr>
                    <th>Phase</th>
                    <th>Custom Total</th>
                    <th>Bandit Total</th>
                    <th>Semgrep Total</th>
                    <th class="highlight-3way">3-Way Overlap</th>
                    <th>Custom-Bandit</th>
                    <th>Custom-Semgrep</th>
                    <th>Bandit-Semgrep</th>
                </tr>
            </thead>
            <tbody>"""
        
        for phase in phases:
            data = phase['data']
            html_content += f"""
                <tr>
                    <td><strong>{phase['name']}</strong></td>
                    <td>{data['custom_total']}</td>
                    <td>{data['bandit_total']}</td>
                    <td>{data['semgrep_total']}</td>
                    <td class="highlight-3way">{data['three_way']}</td>
                    <td>{data['custom_bandit']}</td>
                    <td>{data['custom_semgrep']}</td>
                    <td>{data['bandit_semgrep']}</td>
                </tr>"""
        
        html_content += """
            </tbody>
        </table>

        <h2>Overlap Details by Phase (CWE IDs)</h2>
        <table class="phase-table">
            <thead>
                <tr>
                    <th>Phase</th>
                    <th>3-Way (Custom ∩ Bandit ∩ Semgrep)</th>
                    <th>Custom ∩ Bandit</th>
                    <th>Custom ∩ Semgrep</th>
                    <th>Bandit ∩ Semgrep</th>
                </tr>
            </thead>
            <tbody>"""

        def fmt_list(vals):
            if not vals:
                return "–"
            return ", ".join(sorted(str(v) for v in vals))

        for phase in phases:
            data = phase['data']
            html_content += f"""
                <tr>
                    <td><strong>{phase['name']}</strong></td>
                    <td>{fmt_list(data.get('three_way_list', []))}</td>
                    <td>{fmt_list(data.get('custom_bandit_list', []))}</td>
                    <td>{fmt_list(data.get('custom_semgrep_list', []))}</td>
                    <td>{fmt_list(data.get('bandit_semgrep_list', []))}</td>
                </tr>"""

        html_content += """
            </tbody>
        </table>
        
        <div class="legend">
            <h3>Legend</h3>
            <div class="legend-item">
                <span class="legend-color" style="background-color: #1abc9c;"></span>
                <strong>3-Way Overlap:</strong> CWEs detected by all three tools
            </div>
            <div class="legend-item">
                <span class="legend-color" style="background-color: #3498db;"></span>
                <strong>Custom-Bandit:</strong> CWEs detected by Custom and Bandit only
            </div>
            <div class="legend-item">
                <span class="legend-color" style="background-color: #9b59b6;"></span>
                <strong>Custom-Semgrep:</strong> CWEs detected by Custom and Semgrep only
            </div>
            <div class="legend-item">
                <span class="legend-color" style="background-color: #e74c3c;"></span>
                <strong>Bandit-Semgrep:</strong> CWEs detected by Bandit and Semgrep only
            </div>
        </div>
        
        <h2>Key Insights</h2>
        <ul>"""
        
        # Generate insights
        if len(phases) >= 2:
            initial_3way = phases[0]['data']['three_way']
            final_3way = phases[-1]['data']['three_way']
            change = final_3way - initial_3way
            
            html_content += f"""
            <li><strong>3-Way Agreement Change:</strong> From {initial_3way} CWEs (initial) to {final_3way} CWEs (final) - 
            {'decreased' if change < 0 else 'increased' if change > 0 else 'unchanged'} by {abs(change)} CWEs</li>"""
            
            initial_total_custom = phases[0]['data']['custom_total']
            final_total_custom = phases[-1]['data']['custom_total']
            html_content += f"""
            <li><strong>Custom Detector:</strong> {initial_total_custom} vulnerabilities initially → {final_total_custom} finally</li>"""
            
            initial_total_bandit = phases[0]['data']['bandit_total']
            final_total_bandit = phases[-1]['data']['bandit_total']
            html_content += f"""
            <li><strong>Bandit:</strong> {initial_total_bandit} vulnerabilities initially → {final_total_bandit} finally</li>"""
            
            initial_total_semgrep = phases[0]['data']['semgrep_total']
            final_total_semgrep = phases[-1]['data']['semgrep_total']
            html_content += f"""
            <li><strong>Semgrep:</strong> {initial_total_semgrep} vulnerabilities initially → {final_total_semgrep} finally</li>"""
        
        html_content += """
        </ul>
        
        <script>
            // Overlap Evolution Chart
            const ctx1 = document.getElementById('overlapEvolutionChart').getContext('2d');
            new Chart(ctx1, {
                type: 'line',
                data: {
                    labels: """ + str(phase_labels) + """,
                    datasets: [
                        {
                            label: '3-Way Overlap (All Tools)',
                            data: """ + str(three_way_data) + """,
                            borderColor: '#1abc9c',
                            backgroundColor: 'rgba(26, 188, 156, 0.1)',
                            borderWidth: 3,
                            tension: 0.1
                        },
                        {
                            label: 'Custom-Bandit Overlap',
                            data: """ + str(custom_bandit_data) + """,
                            borderColor: '#3498db',
                            backgroundColor: 'rgba(52, 152, 219, 0.1)',
                            borderWidth: 2,
                            tension: 0.1
                        },
                        {
                            label: 'Custom-Semgrep Overlap',
                            data: """ + str(custom_semgrep_data) + """,
                            borderColor: '#9b59b6',
                            backgroundColor: 'rgba(155, 89, 182, 0.1)',
                            borderWidth: 2,
                            tension: 0.1
                        },
                        {
                            label: 'Bandit-Semgrep Overlap',
                            data: """ + str(bandit_semgrep_data) + """,
                            borderColor: '#e74c3c',
                            backgroundColor: 'rgba(231, 76, 60, 0.1)',
                            borderWidth: 2,
                            tension: 0.1
                        }
                    ]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        title: {
                            display: true,
                            text: 'Tool Agreement Evolution Across Phases',
                            font: { size: 16 }
                        },
                        legend: {
                            position: 'top'
                        }
                    },
                    scales: {
                        y: {
                            beginAtZero: true,
                            title: {
                                display: true,
                                text: 'Number of CWEs'
                            }
                        },
                        x: {
                            title: {
                                display: true,
                                text: 'Analysis Phase'
                            }
                        }
                    }
                }
            });
            
            // Total Vulnerabilities Chart
            const ctx2 = document.getElementById('totalVulnsChart').getContext('2d');
            new Chart(ctx2, {
                type: 'bar',
                data: {
                    labels: """ + str(phase_labels) + """,
                    datasets: [
                        {
                            label: 'Custom Detector',
                            data: """ + str(custom_total_data) + """,
                            backgroundColor: 'rgba(52, 152, 219, 0.7)'
                        },
                        {
                            label: 'Bandit',
                            data: """ + str(bandit_total_data) + """,
                            backgroundColor: 'rgba(231, 76, 60, 0.7)'
                        },
                        {
                            label: 'Semgrep',
                            data: """ + str(semgrep_total_data) + """,
                            backgroundColor: 'rgba(155, 89, 182, 0.7)'
                        }
                    ]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        title: {
                            display: true,
                            text: 'Total Vulnerabilities Per Tool Per Phase',
                            font: { size: 16 }
                        },
                        legend: {
                            position: 'top'
                        }
                    },
                    scales: {
                        y: {
                            beginAtZero: true,
                            title: {
                                display: true,
                                text: 'Number of Vulnerabilities'
                            }
                        },
                        x: {
                            title: {
                                display: true,
                                text: 'Analysis Phase'
                            }
                        }
                    }
                }
            });
        </script>
    </div>
</body>
</html>"""
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        print(f"✅ 3-way overlap evolution report saved: {filename}")
        return filename
    
    def export_overlap_details_report(self, comparison_result: Dict, output_dir: str = "test_reports") -> str:
        """
        Generate detailed report showing which CWEs overlap at which line numbers.
        
        Args:
            comparison_result: Result from compare_three_tools method
            output_dir: Directory to save the report
            
        Returns:
            Path to generated report file
        """
        import datetime
        
        os.makedirs(output_dir, exist_ok=True)
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = os.path.join(output_dir, f"overlap_details_{timestamp}.html")
        
        # Extract details
        custom_bandit_details = comparison_result.get('custom_bandit_overlap_details', [])
        custom_semgrep_details = comparison_result.get('custom_secondary_overlap_details', [])
        bandit_semgrep_details = comparison_result.get('bandit_secondary_overlap_details', [])
        three_way_details = comparison_result.get('three_way_overlap_details', [])
        
        html_content = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Tool Overlap Details Report</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0"></script>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 20px;
            background-color: #f5f5f5;
        }
        .container {
            max-width: 1400px;
            margin: 0 auto;
            background-color: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        h1 {
            color: #2c3e50;
            border-bottom: 3px solid #3498db;
            padding-bottom: 10px;
        }
        h2 {
            color: #34495e;
            margin-top: 30px;
        }
        .overlap-section {
            margin: 30px 0;
            padding: 20px;
            border-left: 5px solid #3498db;
            background-color: #f8f9fa;
        }
        .overlap-section.three-way {
            border-left-color: #1abc9c;
        }
        .overlap-section.custom-bandit {
            border-left-color: #3498db;
        }
        .overlap-section.custom-semgrep {
            border-left-color: #9b59b6;
        }
        .overlap-section.bandit-semgrep {
            border-left-color: #e74c3c;
        }
        .details-table {
            width: 100%;
            border-collapse: collapse;
            margin: 15px 0;
        }
        .details-table th, .details-table td {
            border: 1px solid #ddd;
            padding: 12px;
            text-align: left;
        }
        .details-table th {
            background-color: #34495e;
            color: white;
            font-weight: bold;
        }
        .details-table tr:nth-child(even) {
            background-color: #f9f9f9;
        }
        .cwe-badge {
            display: inline-block;
            background-color: #e74c3c;
            color: white;
            padding: 4px 8px;
            border-radius: 4px;
            font-weight: bold;
            margin-right: 10px;
        }
        .line-badge {
            display: inline-block;
            background-color: #3498db;
            color: white;
            padding: 4px 8px;
            border-radius: 4px;
            font-family: monospace;
        }
        .count-badge {
            font-size: 24px;
            font-weight: bold;
            color: #2c3e50;
        }
        .no-overlaps {
            color: #95a5a6;
            font-style: italic;
            padding: 15px;
        }
        .chart-container {
            position: relative;
            height: 400px;
            margin: 30px 0;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔍 Tool Overlap Details Report</h1>
        <p><strong>Generated:</strong> """ + datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + """</p>
        
        <h2>Overview</h2>
        <div class="chart-container">
            <canvas id="overlapChart"></canvas>
        </div>
        
        <h2>Detailed Overlaps by Tool Pair</h2>"""
        
        # Helper function to generate overlap section
        def generate_overlap_section(title, details, css_class, color):
            html = f"""
        <div class="overlap-section {css_class}">
            <h3>{title}</h3>
            <p><strong>Count: <span class="count-badge">{len(details)}</span> overlapping vulnerabilities</strong></p>
            """
            if details:
                html += """
            <table class="details-table">
                <thead>
                    <tr>
                        <th>CWE ID</th>
                        <th>Line Number</th>
                    </tr>
                </thead>
                <tbody>"""
                for item in details:
                    cwe = item[0] if isinstance(item, tuple) else item.get('cwe', 'Unknown')
                    line = item[1] if isinstance(item, tuple) else item.get('line', 'Unknown')
                    html += f"""
                    <tr>
                        <td><span class="cwe-badge">CWE-{cwe}</span></td>
                        <td><span class="line-badge">Line {line}</span></td>
                    </tr>"""
                html += """
                </tbody>
            </table>"""
            else:
                html += """<p class="no-overlaps">No overlapping vulnerabilities found.</p>"""
            html += """
        </div>"""
            return html
        
        # Generate sections for each overlap type
        html_content += generate_overlap_section(
            "✅ 3-Way Overlap (All Tools Agree)",
            three_way_details,
            "three-way",
            "#1abc9c"
        )
        
        html_content += generate_overlap_section(
            "Custom Detector & Bandit Overlap",
            custom_bandit_details,
            "custom-bandit",
            "#3498db"
        )
        
        html_content += generate_overlap_section(
            "Custom Detector & Semgrep Overlap",
            custom_semgrep_details,
            "custom-semgrep",
            "#9b59b6"
        )
        
        html_content += generate_overlap_section(
            "Bandit & Semgrep Overlap",
            bandit_semgrep_details,
            "bandit-semgrep",
            "#e74c3c"
        )
        
        # Add summary
        html_content += """
        <h2>Summary</h2>
        <table class="details-table">
            <thead>
                <tr>
                    <th>Overlap Type</th>
                    <th>Count</th>
                </tr>
            </thead>
            <tbody>"""
        
        html_content += f"""
                <tr>
                    <td><strong>3-Way Overlap (All Tools)</strong></td>
                    <td>{len(three_way_details)}</td>
                </tr>
                <tr>
                    <td>Custom & Bandit</td>
                    <td>{len(custom_bandit_details)}</td>
                </tr>
                <tr>
                    <td>Custom & Semgrep</td>
                    <td>{len(custom_semgrep_details)}</td>
                </tr>
                <tr>
                    <td>Bandit & Semgrep</td>
                    <td>{len(bandit_semgrep_details)}</td>
                </tr>
            </tbody>
        </table>
        
        <script>
            const ctx = document.getElementById('overlapChart').getContext('2d');
            new Chart(ctx, {{
                type: 'bar',
                data: {{
                    labels: ['3-Way Overlap', 'Custom-Bandit', 'Custom-Semgrep', 'Bandit-Semgrep'],
                    datasets: [{{
                        label: 'Number of Overlapping Vulnerabilities (CWE-Line pairs)',
                        data: [{len(three_way_details)}, {len(custom_bandit_details)}, {len(custom_semgrep_details)}, {len(bandit_semgrep_details)}],
                        backgroundColor: ['#1abc9c', '#3498db', '#9b59b6', '#e74c3c'],
                        borderColor: ['#16a085', '#2980b9', '#8e44ad', '#c0392b'],
                        borderWidth: 2
                    }}]
                }},
                options: {{
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {{
                        title: {{
                            display: true,
                            text: 'Tool Overlap Comparison',
                            font: {{ size: 16 }}
                        }},
                        legend: {{
                            display: true
                        }}
                    }},
                    scales: {{
                        y: {{
                            beginAtZero: true,
                            title: {{
                                display: true,
                                text: 'Count of Overlapping Vulnerabilities'
                            }}
                        }}
                    }}
                }}
            }});
        </script>
    </div>
</body>
</html>"""
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        print(f"✅ Overlap details report saved: {filename}")
        return filename


# Backwards compatibility function
def export_report(vulns, path_base):
    """Export vulnerabilities to CSV and JSON."""
    reporter = VulnerabilityReporter()
    
    if not vulns:
        return None, None
    
    result = reporter.export_vulnerability_report(vulns, os.path.basename(path_base))
    return result.get('csv_path'), result.get('json_path')
