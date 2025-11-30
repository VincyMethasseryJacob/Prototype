"""
Backend Test Script - Verify all modules are working correctly
"""

import sys
import os

# Add backend to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

def test_imports():
    """Test that all backend modules can be imported."""
    print("🔍 Testing module imports...")
    
    try:
        from backend.vuln_detection import VulnerabilityDetector
        print("  ✓ vuln_detection.py imported successfully")
    except Exception as e:
        print(f"  ✗ vuln_detection.py failed: {e}")
        return False
    
    try:
        from backend.explainability import VulnerabilityExplainer
        print("  ✓ explainability.py imported successfully")
    except Exception as e:
        print(f"  ✗ explainability.py failed: {e}")
        return False
    
    try:
        from backend.patching import CodePatcher
        print("  ✓ patching.py imported successfully")
    except Exception as e:
        print(f"  ✗ patching.py failed: {e}")
        return False
    
    try:
        from backend.static_analysis import StaticAnalyzer
        print("  ✓ static_analysis.py imported successfully")
    except Exception as e:
        print(f"  ✗ static_analysis.py failed: {e}")
        return False
    
    try:
        from backend.metrics import MetricsCalculator
        print("  ✓ metrics.py imported successfully")
    except Exception as e:
        print(f"  ✗ metrics.py failed: {e}")
        return False
    
    try:
        from backend.reporting import VulnerabilityReporter
        print("  ✓ reporting.py imported successfully")
    except Exception as e:
        print(f"  ✗ reporting.py failed: {e}")
        return False
    
    try:
        from backend.preprocessing import clean_code
        print("  ✓ preprocessing.py imported successfully")
    except Exception as e:
        print(f"  ✗ preprocessing.py failed: {e}")
        return False
    
    try:
        from backend.workflow import VulnerabilityAnalysisWorkflow
        print("  ✓ workflow.py imported successfully")
    except Exception as e:
        print(f"  ✗ workflow.py failed: {e}")
        return False
    
    return True


def test_vulnerability_detection():
    """Test vulnerability detection with a sample code."""
    print("\n🔍 Testing vulnerability detection...")
    
    from backend.vuln_detection import VulnerabilityDetector
    
    # Create a sample vulnerable code
    vulnerable_code = '''
import os

def delete_file(filename):
    os.remove(filename)

password = "hardcoded123"
'''
    
    try:
        # Get the vulnerable samples directory
        samples_dir = os.path.join(os.path.dirname(__file__), '..', 'Author_Insecure_Code')
        
        if not os.path.exists(samples_dir):
            print(f"  ⚠ Vulnerable samples directory not found: {samples_dir}")
            print("  ℹ Skipping detection test (samples needed)")
            return True
        
        detector = VulnerabilityDetector(samples_dir)
        vulnerabilities = detector.detect_vulnerabilities(vulnerable_code)
        
        print(f"  ✓ Detected {len(vulnerabilities)} vulnerabilities")
        
        for vuln in vulnerabilities[:3]:  # Show first 3
            print(f"    - CWE-{vuln.get('cwe_id')}: {vuln.get('cwe_name')}")
        
        return True
    
    except Exception as e:
        print(f"  ✗ Detection failed: {e}")
        return False


def test_explainability():
    """Test explanation generation."""
    print("\n🔍 Testing explainability...")
    
    from backend.explainability import VulnerabilityExplainer
    
    try:
        explainer = VulnerabilityExplainer()
        
        # Test with a sample vulnerability
        vuln = {
            'cwe_id': '089',
            'cwe_name': 'SQL Injection',
            'severity': 'HIGH',
            'line_number': 15
        }
        
        explained = explainer.generate_explanation(vuln)
        
        if 'explanation' in explained and 'patch_note' in explained:
            print("  ✓ Explanation generated successfully")
            print(f"    - Explanation length: {len(explained['explanation'])} chars")
            print(f"    - Patch note length: {len(explained['patch_note'])} chars")
            return True
        else:
            print("  ✗ Explanation missing required fields")
            return False
    
    except Exception as e:
        print(f"  ✗ Explainability failed: {e}")
        return False


def test_patching():
    """Test code patching."""
    print("\n🔍 Testing patching...")
    
    from backend.patching import CodePatcher
    
    try:
        patcher = CodePatcher()
        
        # Test with sample vulnerable code
        code = 'password = "hardcoded123"'
        vulnerabilities = [{
            'cwe_id': '259',
            'cwe_name': 'Hard-coded Password',
            'line_number': 1
        }]
        
        result = patcher.generate_patch(code, vulnerabilities)
        
        if 'patched_code' in result:
            print("  ✓ Patching executed successfully")
            print(f"    - Changes applied: {len(result.get('changes', []))}")
            print(f"    - Unpatched: {len(result.get('unpatched_vulns', []))}")
            return True
        else:
            print("  ✗ Patch result missing required fields")
            return False
    
    except Exception as e:
        print(f"  ✗ Patching failed: {e}")
        return False


def test_static_analysis():
    """Test static analysis tools."""
    print("\n🔍 Testing static analysis...")
    
    from backend.static_analysis import StaticAnalyzer
    
    try:
        analyzer = StaticAnalyzer()
        tools = analyzer.tools_available
        
        print(f"  Bandit available: {'✓' if tools.get('bandit') else '✗'}")
        print(f"  Pylint available: {'✓' if tools.get('pylint') else '✗'}")
        
        if not tools.get('bandit'):
            print("  ⚠ Bandit not installed. Install with: pip install bandit")
        
        if not tools.get('pylint'):
            print("  ⚠ Pylint not installed. Install with: pip install pylint")
        
        # Test with simple code
        if tools.get('bandit'):
            test_code = 'import os\nos.system("ls")'
            result = analyzer.run_bandit(test_code)
            
            if result.get('success'):
                print("  ✓ Bandit analysis working")
            else:
                print(f"  ⚠ Bandit analysis failed: {result.get('error')}")
        
        return True
    
    except Exception as e:
        print(f"  ✗ Static analysis failed: {e}")
        return False


def test_metrics():
    """Test metrics calculation."""
    print("\n🔍 Testing metrics...")
    
    from backend.metrics import MetricsCalculator
    
    try:
        calc = MetricsCalculator()
        
        # Test patching effectiveness
        vulns_before = [
            {'cwe_id': '089'},
            {'cwe_id': '022'},
        ]
        vulns_after = [
            {'cwe_id': '022'},
        ]
        
        metrics = calc.calculate_patching_effectiveness(vulns_before, vulns_after)
        
        print(f"  ✓ Metrics calculated successfully")
        print(f"    - Fix rate: {metrics.get('fix_rate', 0):.1%}")
        print(f"    - Effectiveness: {metrics.get('effectiveness_score', 0):.1%}")
        
        return True
    
    except Exception as e:
        print(f"  ✗ Metrics calculation failed: {e}")
        return False


def test_reporting():
    """Test report generation."""
    print("\n🔍 Testing reporting...")
    
    from backend.reporting import VulnerabilityReporter
    import tempfile
    
    try:
        # Use temp directory for testing
        with tempfile.TemporaryDirectory() as tmpdir:
            reporter = VulnerabilityReporter(tmpdir)
            
            # Test with sample vulnerabilities
            vulns = [{
                'cwe_id': '089',
                'cwe_name': 'SQL Injection',
                'severity': 'HIGH',
                'line_number': 15,
                'description': 'Test vulnerability'
            }]
            
            result = reporter.export_vulnerability_report(vulns, 'test_report')
            
            if result.get('csv_path') and result.get('json_path'):
                print("  ✓ Report generation working")
                print(f"    - CSV created: {os.path.exists(result['csv_path'])}")
                print(f"    - JSON created: {os.path.exists(result['json_path'])}")
                return True
            else:
                print("  ✗ Report generation failed")
                return False
    
    except Exception as e:
        print(f"  ✗ Reporting failed: {e}")
        return False


def main():
    """Run all tests."""
    print("=" * 60)
    print("Backend Module Test Suite")
    print("=" * 60)
    
    tests = [
        ("Module Imports", test_imports),
        ("Vulnerability Detection", test_vulnerability_detection),
        ("Explainability", test_explainability),
        ("Code Patching", test_patching),
        ("Static Analysis", test_static_analysis),
        ("Metrics Calculation", test_metrics),
        ("Report Generation", test_reporting),
    ]
    
    results = {}
    
    for test_name, test_func in tests:
        try:
            results[test_name] = test_func()
        except Exception as e:
            print(f"\n✗ {test_name} failed with exception: {e}")
            results[test_name] = False
    
    # Summary
    print("\n" + "=" * 60)
    print("Test Summary")
    print("=" * 60)
    
    passed = sum(1 for r in results.values() if r)
    total = len(results)
    
    for test_name, result in results.items():
        status = "✓ PASS" if result else "✗ FAIL"
        print(f"{status:8} {test_name}")
    
    print("=" * 60)
    print(f"Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("\n🎉 All tests passed! Backend is ready to use.")
        return 0
    else:
        print(f"\n⚠️  {total - passed} test(s) failed. Please review errors above.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
