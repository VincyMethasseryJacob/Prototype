"""
Static Analysis module: Runs Bandit and secondary tool (Semgrep) for vulnerability detection.
"""
import subprocess
import tempfile
import json
import os
import re
from typing import Dict, List


def strip_markdown_code_fences(code: str) -> str:
    """
    Remove markdown code fences from code string.
    
    Args:
        code: Code string that may contain markdown fences like ```python or ```
    
    Returns:
        Clean code without markdown fences
    """
    # Remove opening fence with optional language specifier
    code = re.sub(r'^```[\w]*\s*\n', '', code, flags=re.MULTILINE)
    # Remove closing fence
    code = re.sub(r'\n```\s*$', '', code, flags=re.MULTILINE)
    # Also handle fences in the middle
    code = re.sub(r'```[\w]*\s*\n', '', code)
    code = re.sub(r'\n```', '', code)
    
    return code.strip()


class StaticAnalyzer:
    """
    Runs static analysis tools on code to detect vulnerabilities.
    Supports Bandit (primary) and Semgrep (secondary).
    """
    
    def __init__(self):
        self.tools_available = self._check_tools()
    
    def _check_tools(self) -> Dict[str, bool]:
        """Check which static analysis tools are available."""
        tools = {}
        
        # Check Bandit
        try:
            subprocess.run(['bandit', '--version'], capture_output=True, check=True)
            tools['bandit'] = True
        except (subprocess.CalledProcessError, FileNotFoundError):
            tools['bandit'] = False
        
        # Check Semgrep
        try:
            subprocess.run(['semgrep', '--version'], capture_output=True, check=True)
            tools['semgrep'] = True
        except (subprocess.CalledProcessError, FileNotFoundError):
            tools['semgrep'] = False
        
        return tools
    
    def run_bandit(self, code: str, code_path: str = None) -> Dict:
        """
        Run Bandit on the given code and return results.
        
        Args:
            code: Python code string to analyze
            code_path: Optional path to existing file (if None, creates temp file)
        
        Returns:
            Dict with 'issues', 'summary', 'raw_output', and 'success'
        """
        if not self.tools_available.get('bandit', False):
            return {
                'success': False,
                'error': 'Bandit is not installed. Install with: pip install bandit',
                'issues': [],
                'summary': {}
            }
        
        # Strip markdown code fences if present
        code = strip_markdown_code_fences(code)
        
        # Create temporary file if no path provided
        temp_file = None
        if code_path is None:
            temp_file = tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False, encoding='utf-8')
            temp_file.write(code)
            temp_file.flush()
            code_path = temp_file.name
        
        try:
            # Run Bandit with JSON output
            result = subprocess.run(
                ['bandit', '-r', code_path, '-f', 'json'],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            # Bandit returns non-zero if issues found, which is expected
            output = result.stdout
            
            try:
                bandit_data = json.loads(output)
            except json.JSONDecodeError:
                return {
                    'success': False,
                    'error': 'Failed to parse Bandit output',
                    'raw_output': output,
                    'issues': [],
                    'summary': {}
                }
            
            # Extract issues
            issues = []
            for result_item in bandit_data.get('results', []):
                issues.append({
                    'test_id': result_item.get('test_id'),
                    'test_name': result_item.get('test_name'),
                    'severity': result_item.get('issue_severity'),
                    'confidence': result_item.get('issue_confidence'),
                    'cwe_id': result_item.get('issue_cwe', {}).get('id') if result_item.get('issue_cwe') else None,
                    'line_number': result_item.get('line_number'),
                    'code': result_item.get('code'),
                    'description': result_item.get('issue_text'),
                    'more_info': result_item.get('more_info')
                })
            
            # Extract summary
            metrics = bandit_data.get('metrics', {})
            total_issues = sum(
                sum(sev_dict.values())
                for file_metrics in metrics.values()
                for sev_dict in [file_metrics.get('SEVERITY', {})]
            )
            
            summary = {
                'total_issues': total_issues,
                'severity_breakdown': self._aggregate_severity(bandit_data),
                'confidence_breakdown': self._aggregate_confidence(bandit_data),
                'files_analyzed': len(metrics)
            }
            
            return {
                'success': True,
                'issues': issues,
                'summary': summary,
                'raw_output': output
            }
        
        except subprocess.TimeoutExpired:
            return {
                'success': False,
                'error': 'Bandit analysis timed out',
                'issues': [],
                'summary': {}
            }
        except Exception as e:
            return {
                'success': False,
                'error': f'Error running Bandit: {str(e)}',
                'issues': [],
                'summary': {}
            }
        finally:
            # Clean up temporary file
            if temp_file:
                try:
                    os.unlink(temp_file.name)
                except:
                    pass
    
    def _aggregate_severity(self, bandit_data: Dict) -> Dict[str, int]:
        """Aggregate severity counts from Bandit data."""
        severity_counts = {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'UNDEFINED': 0}
        
        for result in bandit_data.get('results', []):
            severity = result.get('issue_severity', 'UNDEFINED')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        return severity_counts
    
    def _aggregate_confidence(self, bandit_data: Dict) -> Dict[str, int]:
        """Aggregate confidence counts from Bandit data."""
        confidence_counts = {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'UNDEFINED': 0}
        
        for result in bandit_data.get('results', []):
            confidence = result.get('issue_confidence', 'UNDEFINED')
            confidence_counts[confidence] = confidence_counts.get(confidence, 0) + 1
        
        return confidence_counts
    
    def run_semgrep(self, code: str, code_path: str = None, config: str = "auto") -> Dict:
        """
        Run Semgrep on the given code and return results.
        
        Args:
            code: Python code string to analyze
            code_path: Optional path to existing file
            config: Semgrep config (default "auto" uses built-in rules). You can pass a ruleset or path.
        
        Returns:
            Dict with 'issues', 'summary', 'raw_output', and 'success'
        """
        if not self.tools_available.get('semgrep', False):
            return {
                'success': False,
                'error': 'Semgrep is not installed. Install from https://semgrep.dev/docs/ or via pip/installer',
                'issues': [],
                'summary': {}
            }

        code = strip_markdown_code_fences(code)

        temp_file = None
        if code_path is None:
            temp_file = tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False, encoding='utf-8')
            temp_file.write(code)
            temp_file.flush()
            code_path = temp_file.name

        try:
            # Semgrep JSON output
            env = os.environ.copy()
            env.setdefault('PYTHONIOENCODING', 'utf-8')
            env.setdefault('PYTHONUTF8', '1')
            result = subprocess.run(
                ['semgrep', '--json', '--config', config, code_path],
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='replace',
                timeout=60,
                env=env
            )
            output = result.stdout

            try:
                data = json.loads(output) if output.strip() else {}
            except json.JSONDecodeError:
                return {
                    'success': False,
                    'error': 'Failed to parse Semgrep output',
                    'raw_output': output,
                    'issues': [],
                    'summary': {}
                }

            findings = []
            # Map Semgrep severity to Bandit-style
            semgrep_severity_map = {
                'ERROR': 'HIGH',
                'WARNING': 'MEDIUM',
                'INFO': 'LOW',
                'MEDIUM': 'MEDIUM',
                'HIGH': 'HIGH',
                'LOW': 'LOW'
            }
            for r in data.get('results', []):
                extra = r.get('extra', {})
                raw_severity = (extra.get('severity') or 'MEDIUM').upper()
                severity = semgrep_severity_map.get(raw_severity, 'MEDIUM')
                # semgrep often includes metadata.cwe: ["CWE-089"]
                meta = extra.get('metadata', {})
                cwes = meta.get('cwe') or []
                cwe_id = None
                if isinstance(cwes, list) and cwes:
                    first = str(cwes[0])
                    if first.upper().startswith('CWE-'):
                        cwe_id = first[4:]
                    else:
                        cwe_id = first

                findings.append({
                    'check_id': r.get('check_id'),
                    'path': r.get('path'),
                    'start': r.get('start', {}),
                    'end': r.get('end', {}),
                    'severity': severity,
                    'message': extra.get('message') or '',
                    'cwe_id': cwe_id,
                })

            summary = {
                'total_issues': len(findings),
                'severity_breakdown': {
                    'HIGH': sum(1 for f in findings if f['severity'] == 'HIGH'),
                    'MEDIUM': sum(1 for f in findings if f['severity'] == 'MEDIUM'),
                    'LOW': sum(1 for f in findings if f['severity'] == 'LOW')
                }
            }

            return {
                'success': True,
                'issues': findings,
                'summary': summary,
                'raw_output': output
            }
        except subprocess.TimeoutExpired:
            return {
                'success': False,
                'error': 'Semgrep analysis timed out',
                'issues': [],
                'summary': {}
            }
        except Exception as e:
            return {
                'success': False,
                'error': f'Error running Semgrep: {str(e)}',
                'issues': [],
                'summary': {}
            }
        finally:
            if temp_file:
                try:
                    os.unlink(temp_file.name)
                except:
                    pass
    
    def run_secondary_tool(self, code: str, tool: str = 'semgrep') -> Dict:
        """
        Run a secondary static analyzer.
        
        Args:
            code: Python code to analyze
            tool: Tool name ('semgrep' is currently supported)
        
        Returns:
            Analysis results dictionary
        """
        if tool.lower() == 'semgrep':
            return self.run_semgrep(code)
        else:
            return {
                'success': False,
                'error': f'Tool {tool} not supported',
                'issues': [],
                'summary': {}
            }
    
    def compare_results(self, bandit_results: Dict, secondary_results: Dict) -> Dict:
        """
        Compare results from Bandit and secondary tool to identify overlaps and differences.
        
        Returns:
            Dict with comparison statistics
        """
        bandit_issues = bandit_results.get('issues', [])
        secondary_issues = secondary_results.get('issues', [])
        
        # Extract CWE IDs from both
        bandit_cwes = set(issue.get('cwe_id') for issue in bandit_issues if issue.get('cwe_id'))
        
        # Map Semgrep issues to approximate CWE categories (simplified)
        secondary_lines = set(issue.get('line_number') for issue in secondary_issues)
        bandit_lines = set(issue.get('line_number') for issue in bandit_issues)
        
        overlapping_lines = bandit_lines.intersection(secondary_lines)
        
        return {
            'bandit_total': len(bandit_issues),
            'secondary_total': len(secondary_issues),
            'bandit_unique_cwes': len(bandit_cwes),
            'overlapping_lines': len(overlapping_lines),
            'bandit_only_lines': len(bandit_lines - secondary_lines),
            'secondary_only_lines': len(secondary_lines - bandit_lines),
            'bandit_severity': bandit_results.get('summary', {}).get('severity_breakdown', {}),
            'secondary_types': secondary_results.get('summary', {}).get('type_breakdown', {})
        }


# Backwards compatibility functions
def run_bandit(code_path: str) -> dict:
    """
    Run Bandit on the given code file and return results.
    """
    analyzer = StaticAnalyzer()
    with open(code_path, 'r', encoding='utf-8') as f:
        code = f.read()
    return analyzer.run_bandit(code, code_path)


def run_secondary_tool(code_path: str) -> dict:
    """
    Run a secondary static analyzer (Semgrep) and return results.
    """
    analyzer = StaticAnalyzer()
    with open(code_path, 'r', encoding='utf-8') as f:
        code = f.read()
    return analyzer.run_semgrep(code, code_path)
