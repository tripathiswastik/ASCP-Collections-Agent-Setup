"""
Python Version: 3.10+ (Target: Python 3.10, 3.11, 3.12)
Purpose: Test runner script to discover and execute all unit and integration test suites for Autonomous Oracle ASCP Diagnostic Agent.
Runs-in: Local development shell, CI test runner, or autonomous agent evaluation runtime.
"""

import unittest
import sys
import os

# Add parent directory to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

def run_tests():
    loader = unittest.TestLoader()
    start_dir = os.path.dirname(__file__)
    suite = loader.discover(start_dir, pattern="test_*.py")

    print("\n" + "=" * 80)
    print("  RUNNING AUTONOMOUS ASCP DIAGNOSTIC AGENT TEST SUITE")
    print("=" * 80 + "\n")

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    print("\n" + "=" * 80)
    if result.wasSuccessful():
        print(f"  [SUCCESS] All {result.testsRun} tests passed successfully!")
    else:
        print(f"  [FAILURE] Tests failed: {len(result.failures)} failures, {len(result.errors)} errors.")
    print("=" * 80 + "\n")

    return 0 if result.wasSuccessful() else 1

if __name__ == "__main__":
    sys.exit(run_tests())
