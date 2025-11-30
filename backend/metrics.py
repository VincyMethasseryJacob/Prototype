"""
Metrics module: Calculates precision, recall, F1, and generates summary charts/tables.
"""

from typing import List, Dict


class MetricsCalculator:
    """
    Calculate various metrics for vulnerability detection and patching effectiveness.
    """
    
    @staticmethod
    def calculate_detection_metrics(
        detected_vulns: List[Dict],
        ground_truth_vulns: List[Dict]
    ) -> Dict:
        """
        Calculate precision, recall, F1-score for vulnerability detection.
        
        Args:
            detected_vulns: List of vulnerabilities detected by the system
            ground_truth_vulns: List of actual vulnerabilities (ground truth)
        
        Returns:
            Dict with precision, recall, F1, accuracy, and detailed breakdown
        """
        if not ground_truth_vulns:
            return {
                'precision': 1.0 if not detected_vulns else 0.0,
                'recall': 0.0,
                'f1_score': 0.0,
                'accuracy': 1.0 if not detected_vulns else 0.0,
                'true_positives': 0,
                'false_positives': len(detected_vulns),
                'false_negatives': 0,
                'true_negatives': 0
            }
        
        # Extract CWE IDs for comparison
        detected_cwes = set(v.get('cwe_id') for v in detected_vulns if v.get('cwe_id'))
        ground_truth_cwes = set(v.get('cwe_id') for v in ground_truth_vulns if v.get('cwe_id'))
        
        # Calculate confusion matrix
        true_positives = len(detected_cwes.intersection(ground_truth_cwes))
        false_positives = len(detected_cwes - ground_truth_cwes)
        false_negatives = len(ground_truth_cwes - detected_cwes)
        
        # Calculate metrics
        precision = true_positives / (true_positives + false_positives) if (true_positives + false_positives) > 0 else 0.0
        recall = true_positives / (true_positives + false_negatives) if (true_positives + false_negatives) > 0 else 0.0
        f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
        
        total = len(ground_truth_cwes) + len(detected_cwes - ground_truth_cwes)
        accuracy = true_positives / total if total > 0 else 0.0
        
        return {
            'precision': round(precision, 3),
            'recall': round(recall, 3),
            'f1_score': round(f1_score, 3),
            'accuracy': round(accuracy, 3),
            'true_positives': true_positives,
            'false_positives': false_positives,
            'false_negatives': false_negatives,
            'detected_count': len(detected_vulns),
            'ground_truth_count': len(ground_truth_vulns),
            'unique_cwes_detected': len(detected_cwes),
            'unique_cwes_ground_truth': len(ground_truth_cwes)
        }
    
    @staticmethod
    def calculate_patching_effectiveness(
        vulns_before: List[Dict],
        vulns_after: List[Dict]
    ) -> Dict:
        """
        Calculate effectiveness of patching by comparing vulnerabilities before and after.
        
        Returns:
            Dict with fix rate, remaining vulnerabilities, and breakdown
        """
        if not vulns_before:
            return {
                'fix_rate': 1.0,
                'vulnerabilities_fixed': 0,
                'vulnerabilities_remaining': len(vulns_after),
                'total_vulnerabilities': 0,
                'effectiveness_score': 1.0
            }
        
        cwes_before = set(v.get('cwe_id') for v in vulns_before if v.get('cwe_id'))
        cwes_after = set(v.get('cwe_id') for v in vulns_after if v.get('cwe_id'))
        
        fixed_cwes = cwes_before - cwes_after
        remaining_cwes = cwes_after.intersection(cwes_before)
        new_cwes = cwes_after - cwes_before  # Issues introduced by patching
        
        fix_rate = len(fixed_cwes) / len(cwes_before) if cwes_before else 0.0
        
        # Penalize if new vulnerabilities were introduced
        effectiveness = fix_rate - (len(new_cwes) * 0.1)  # Penalty for new issues
        effectiveness = max(0.0, min(1.0, effectiveness))
        
        return {
            'fix_rate': round(fix_rate, 3),
            'vulnerabilities_fixed': len(fixed_cwes),
            'vulnerabilities_remaining': len(remaining_cwes),
            'new_vulnerabilities': len(new_cwes),
            'total_vulnerabilities': len(cwes_before),
            'effectiveness_score': round(effectiveness, 3),
            'fixed_cwe_ids': sorted(fixed_cwes),
            'remaining_cwe_ids': sorted(remaining_cwes),
            'new_cwe_ids': sorted(new_cwes)
        }
    
    @staticmethod
    def calculate_tool_comparison_metrics(
        primary_tool_results: Dict,
        secondary_tool_results: Dict
    ) -> Dict:
        """
        Compare detection capabilities of two static analysis tools.
        
        Returns:
            Dict with comparison metrics and overlap analysis
        """
        primary_issues = primary_tool_results.get('issues', [])
        secondary_issues = secondary_tool_results.get('issues', [])
        
        # Extract line numbers for comparison
        primary_lines = set(issue.get('line_number') for issue in primary_issues if issue.get('line_number'))
        secondary_lines = set(issue.get('line_number') for issue in secondary_issues if issue.get('line_number'))
        
        overlap = primary_lines.intersection(secondary_lines)
        primary_only = primary_lines - secondary_lines
        secondary_only = secondary_lines - primary_lines
        
        total_unique = len(primary_lines.union(secondary_lines))
        
        overlap_rate = len(overlap) / total_unique if total_unique > 0 else 0.0
        
        return {
            'primary_tool_issues': len(primary_issues),
            'secondary_tool_issues': len(secondary_issues),
            'overlapping_detections': len(overlap),
            'primary_unique_detections': len(primary_only),
            'secondary_unique_detections': len(secondary_only),
            'overlap_rate': round(overlap_rate, 3),
            'total_unique_issues': total_unique,
            'primary_tool_summary': primary_tool_results.get('summary', {}),
            'secondary_tool_summary': secondary_tool_results.get('summary', {})
        }
    
    @staticmethod
    def generate_severity_breakdown(vulnerabilities: List[Dict]) -> Dict:
        """
        Generate a breakdown of vulnerabilities by severity level.
        """
        breakdown = {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'UNDEFINED': 0}
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'UNDEFINED')
            breakdown[severity] = breakdown.get(severity, 0) + 1
        
        return breakdown
    
    @staticmethod
    def generate_cwe_breakdown(vulnerabilities: List[Dict]) -> Dict:
        """
        Generate a breakdown of vulnerabilities by CWE category.
        """
        breakdown = {}
        
        for vuln in vulnerabilities:
            cwe_id = vuln.get('cwe_id', 'Unknown')
            cwe_name = vuln.get('cwe_name', f'CWE-{cwe_id}')
            key = f"{cwe_id}: {cwe_name}"
            breakdown[key] = breakdown.get(key, 0) + 1
        
        return breakdown
    
    @staticmethod
    def calculate_comprehensive_metrics(
        detected_vulns: List[Dict],
        vulns_after_patch: List[Dict],
        primary_tool_results: Dict,
        secondary_tool_results: Dict
    ) -> Dict:
        """
        Calculate comprehensive metrics for the entire workflow.
        
        Returns:
            Dict with all metrics combined
        """
        # Patching effectiveness
        patching_metrics = MetricsCalculator.calculate_patching_effectiveness(
            detected_vulns, vulns_after_patch
        )
        
        # Tool comparison
        tool_comparison = MetricsCalculator.calculate_tool_comparison_metrics(
            primary_tool_results, secondary_tool_results
        )
        
        # Severity and CWE breakdowns
        severity_before = MetricsCalculator.generate_severity_breakdown(detected_vulns)
        severity_after = MetricsCalculator.generate_severity_breakdown(vulns_after_patch)
        cwe_breakdown = MetricsCalculator.generate_cwe_breakdown(detected_vulns)
        
        return {
            'patching_effectiveness': patching_metrics,
            'tool_comparison': tool_comparison,
            'severity_before_patch': severity_before,
            'severity_after_patch': severity_after,
            'cwe_distribution': cwe_breakdown,
            'total_detected': len(detected_vulns),
            'total_after_patch': len(vulns_after_patch),
            'overall_success_rate': patching_metrics.get('effectiveness_score', 0.0)
        }


# Backwards compatibility function
def calculate_metrics(detected: list, fixed: list) -> dict:
    """
    Calculate precision, recall, F1-score, and accuracy.
    """
    calculator = MetricsCalculator()
    return calculator.calculate_patching_effectiveness(detected, fixed)
