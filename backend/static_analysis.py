"""
Static Analysis module: Runs Bandit and secondary tools (Pylint) for vulnerability detection.
"""
import subprocess
import tempfile
import json
import os
from typing import Dict, List


class StaticAnalyzer:
    """
    Runs static analysis tools on code to detect vulnerabilities.
    Supports Bandit (primary) and Pylint (secondary).
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
        
        # Check Pylint
        try:
            subprocess.run(['pylint', '--version'], capture_output=True, check=True)
            tools['pylint'] = True
        except (subprocess.CalledProcessError, FileNotFoundError):
            tools['pylint'] = False
        
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
    
    def run_pylint(self, code: str, code_path: str = None) -> Dict:
        """
        Run Pylint on the given code and return results.
        
        Args:
            code: Python code string to analyze
            code_path: Optional path to existing file
        
        Returns:
            Dict with 'issues', 'summary', 'raw_output', and 'success'
        """
        if not self.tools_available.get('pylint', False):
            return {
                'success': False,
                'error': 'Pylint is not installed. Install with: pip install pylint',
                'issues': [],
                'summary': {}
            }
        
        # Create temporary file if no path provided
        temp_file = None
        if code_path is None:
            temp_file = tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False, encoding='utf-8')
            temp_file.write(code)
            temp_file.flush()
            code_path = temp_file.name
        
        try:
            # Run Pylint with JSON output
            result = subprocess.run(
                ['pylint', code_path, '--output-format=json', '--disable=C,R'],  # Disable convention and refactor
                capture_output=True,
                text=True,
                timeout=30
            )
            
            output = result.stdout
            
            try:
                pylint_data = json.loads(output) if output.strip() else []
            except json.JSONDecodeError:
                return {
                    'success': False,
                    'error': 'Failed to parse Pylint output',
                    'raw_output': output,
                    'issues': [],
                    'summary': {}
                }
            
            # Extract issues (focus on errors and warnings)
            issues = []
            for item in pylint_data:
                msg_type = item.get('type', '')
                if msg_type in ['error', 'warning', 'fatal']:
                    issues.append({
                        'type': msg_type,
                        'module': item.get('module'),
                        'line_number': item.get('line'),
                        'column': item.get('column'),
                        'message_id': item.get('message-id'),
                        'symbol': item.get('symbol'),
                        'description': item.get('message'),
                        'path': item.get('path')
                    })
            
            # Create summary
            type_counts = {}
            for issue in issues:
                issue_type = issue['type']
                type_counts[issue_type] = type_counts.get(issue_type, 0) + 1
            
            summary = {
                'total_issues': len(issues),
                'type_breakdown': type_counts
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
                'error': 'Pylint analysis timed out',
                'issues': [],
                'summary': {}
            }
        except Exception as e:
            return {
                'success': False,
                'error': f'Error running Pylint: {str(e)}',
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
    
    def run_secondary_tool(self, code: str, tool: str = 'pylint') -> Dict:
        """
        Run a secondary static analyzer.
        
        Args:
            code: Python code to analyze
            tool: Tool name ('pylint' is currently supported)
        
        Returns:
            Analysis results dictionary
        """
        if tool.lower() == 'pylint':
            return self.run_pylint(code)
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
        
        # Map Pylint issues to approximate CWE categories (simplified)
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
    Run a secondary static analyzer (Pylint) and return results.
    """
    analyzer = StaticAnalyzer()
    with open(code_path, 'r', encoding='utf-8') as f:
        code = f.read()
    return analyzer.run_pylint(code, code_path)
