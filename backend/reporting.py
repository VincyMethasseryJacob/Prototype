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
        Export comprehensive metrics report.
        """
        if not filename_base:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename_base = f"metrics_report_{timestamp}"
        
        report_path = os.path.join(self.output_dir, f"{filename_base}.json")
        csv_path = os.path.join(self.output_dir, f"{filename_base}.csv")
        
        # Export JSON
        with open(report_path, 'w', encoding='utf-8') as f:
            json.dump(metrics, f, indent=2, ensure_ascii=False)
        
        # Export CSV summary
        summary_rows = []
        
        # Patching effectiveness
        if 'patching_effectiveness' in metrics:
            pe = metrics['patching_effectiveness']
            summary_rows.append({
                'metric_category': 'Patching Effectiveness',
                'metric_name': 'Fix Rate',
                'value': pe.get('fix_rate', 0)
            })
            summary_rows.append({
                'metric_category': 'Patching Effectiveness',
                'metric_name': 'Effectiveness Score',
                'value': pe.get('effectiveness_score', 0)
            })
        
        # Tool comparison
        if 'tool_comparison' in metrics:
            tc = metrics['tool_comparison']
            summary_rows.append({
                'metric_category': 'Tool Comparison',
                'metric_name': 'Overlap Rate',
                'value': tc.get('overlap_rate', 0)
            })
        
        if summary_rows:
            with open(csv_path, 'w', newline='', encoding='utf-8') as csvfile:
                fieldnames = ['metric_category', 'metric_name', 'value']
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(summary_rows)
        
        return report_path
    
    def generate_html_summary(
        self,
        vulnerabilities: List[Dict],
        patch_info: Dict,
        metrics: Dict
    ) -> str:
        """
        Generate an HTML summary report for easy viewing.
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        html_path = os.path.join(self.output_dir, f"summary_report_{timestamp}.html")
        
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Vulnerability Analysis Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        h1 {{ color: #333; }}
        h2 {{ color: #666; border-bottom: 2px solid #ddd; padding-bottom: 5px; }}
        table {{ border-collapse: collapse; width: 100%; margin-bottom: 20px; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #4CAF50; color: white; }}
        .high {{ color: red; font-weight: bold; }}
        .medium {{ color: orange; }}
        .low {{ color: green; }}
        .metric {{ background-color: #f0f0f0; padding: 10px; margin: 10px 0; border-radius: 5px; }}
    </style>
</head>
<body>
    <h1>LLM Code Vulnerability Analysis Report</h1>
    <p>Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
    
    <h2>Summary</h2>
    <div class="metric">
        <p><strong>Total Vulnerabilities Detected:</strong> {len(vulnerabilities)}</p>
        <p><strong>Vulnerabilities Fixed:</strong> {patch_info.get('changes_count', 0)}</p>
        <p><strong>Remaining Vulnerabilities:</strong> {patch_info.get('unpatched_count', 0)}</p>
        <p><strong>Overall Success Rate:</strong> {metrics.get('overall_success_rate', 0):.2%}</p>
    </div>
    
    <h2>Detected Vulnerabilities</h2>
    <table>
        <tr>
            <th>CWE ID</th>
            <th>CWE Name</th>
            <th>Severity</th>
            <th>Line</th>
            <th>Description</th>
        </tr>
        {''.join(self._generate_html_vuln_rows(vulnerabilities))}
    </table>
    
    <h2>Severity Distribution</h2>
    <div class="metric">
        {self._generate_severity_html(metrics.get('severity_before_patch', {}))}
    </div>
</body>
</html>
"""
        
        with open(html_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return html_path
    
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


# Backwards compatibility function
def export_report(vulns, path_base):
    """Export vulnerabilities to CSV and JSON."""
    reporter = VulnerabilityReporter()
    
    if not vulns:
        return None, None
    
    result = reporter.export_vulnerability_report(vulns, os.path.basename(path_base))
    return result.get('csv_path'), result.get('json_path')
