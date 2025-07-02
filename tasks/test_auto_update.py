#!/usr/bin/env python3
"""
Test script for the auto_update.py functionality.
This script creates test notebooks and validates the date update functionality.
"""

import os
import sys
import shutil
import tempfile
import unittest
from datetime import datetime

# Add the tasks directory to the path so we can import auto_update
sys.path.insert(0, os.path.dirname(__file__))
from auto_update import update_text, MONTHS

class TestAutoUpdate(unittest.TestCase):
    """Test cases for the auto-update functionality."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.test_dir = tempfile.mkdtemp()
        
    def tearDown(self):
        """Clean up test fixtures."""
        shutil.rmtree(self.test_dir)
    
    def test_new_format_date_updates(self):
        """Test updating the new configuration format dates."""
        # Sample content with new format
        content = '''# ===== DATE CONFIGURATION =====
# UPDATE THESE VALUES WHEN CREATING NEW MONTHLY NOTEBOOKS
ANALYSIS_YEAR = 2025
ANALYSIS_MONTH = 6  # June = 6
MONTH_NAME = "June"

## June 2025 CVE Data

print(f"Analyzing {MONTH_NAME} {ANALYSIS_YEAR}")
'''
        
        # Test June -> July update
        june_dt = datetime(2025, 6, 1)
        july_dt = datetime(2025, 7, 1)
        
        result = update_text(content, june_dt, july_dt)
        
        # Verify updates
        self.assertIn('ANALYSIS_YEAR = 2025', result)
        self.assertIn('ANALYSIS_MONTH = 7', result)
        self.assertIn('MONTH_NAME = "July"', result)
        self.assertIn('## July 2025 CVE Data', result)
        
        # Ensure old values are gone
        self.assertNotIn('ANALYSIS_MONTH = 6', result)
        self.assertNotIn('MONTH_NAME = "June"', result)
        self.assertNotIn('## June 2025 CVE Data', result)
    
    def test_year_rollover(self):
        """Test updating dates across year boundaries."""
        content = '''# ===== DATE CONFIGURATION =====
ANALYSIS_YEAR = 2025
ANALYSIS_MONTH = 12  # December = 12
MONTH_NAME = "December"

## December 2025 CVE Data
'''
        
        # Test December 2025 -> January 2026
        dec_dt = datetime(2025, 12, 1)
        jan_dt = datetime(2026, 1, 1)
        
        result = update_text(content, dec_dt, jan_dt)
        
        # Verify year rollover
        self.assertIn('ANALYSIS_YEAR = 2026', result)
        self.assertIn('ANALYSIS_MONTH = 1', result)
        self.assertIn('MONTH_NAME = "January"', result)
        self.assertIn('## January 2026 CVE Data', result)
    
    def test_legacy_format_compatibility(self):
        """Test that legacy date formats are still updated."""
        content = '''startdate = pd.Timestamp('2025-06-01')
enddate = pd.Timestamp('2025-07-01')
startdate = date(2025, 6, 1)
enddate  = date(2025, 7, 1)
'''
        
        june_dt = datetime(2025, 6, 1)
        july_dt = datetime(2025, 7, 1)
        
        result = update_text(content, june_dt, july_dt)
        
        # Should update legacy formats
        # Start dates should move from June to July
        self.assertIn("startdate = pd.Timestamp('2025-07-01')", result)
        self.assertIn("startdate = date(2025, 7, 1)", result)
        # End dates should move from July to August
        self.assertIn("enddate = pd.Timestamp('2025-08-01')", result)
        self.assertIn("enddate  = date(2025, 8, 1)", result)
    
    def test_complete_notebook_update(self):
        """Test updating a complete notebook structure."""
        notebook_content = '''{
 "cells": [
  {
   "cell_type": "markdown",
   "metadata": {},
   "source": [
    "## June 2025 CVE Data"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": null,
   "metadata": {},
   "source": [
    "# ===== DATE CONFIGURATION =====\\n",
    "# UPDATE THESE VALUES WHEN CREATING NEW MONTHLY NOTEBOOKS\\n",
    "ANALYSIS_YEAR = 2025\\n",
    "ANALYSIS_MONTH = 6  # June = 6\\n",
    "MONTH_NAME = \\"June\\"\\n",
    "\\n",
    "# ===== IMPORTS AND SETUP =====\\n"
   ]
  }
 ],
 "metadata": {},
 "nbformat": 4,
 "nbformat_minor": 4
}'''
        
        june_dt = datetime(2025, 6, 1)
        july_dt = datetime(2025, 7, 1)
        
        result = update_text(notebook_content, june_dt, july_dt)
        
        # Verify notebook JSON structure is preserved
        self.assertIn('"cells":', result)
        self.assertIn('"metadata":', result)
        
        # Verify date updates within the JSON
        self.assertIn('ANALYSIS_YEAR = 2025', result)
        self.assertIn('ANALYSIS_MONTH = 7', result)
        self.assertIn('MONTH_NAME = \\"July\\"', result)
        self.assertIn('## July 2025 CVE Data', result)
    
    def test_all_month_transitions(self):
        """Test all month-to-month transitions."""
        for i in range(12):
            current_month = i + 1
            next_month = 1 if current_month == 12 else current_month + 1
            current_year = 2025
            next_year = 2026 if current_month == 12 else 2025
            
            content = f'''ANALYSIS_YEAR = {current_year}
ANALYSIS_MONTH = {current_month}
MONTH_NAME = "{MONTHS[current_month-1]}"
## {MONTHS[current_month-1]} {current_year} CVE Data'''
            
            current_dt = datetime(current_year, current_month, 1)
            next_dt = datetime(next_year, next_month, 1)
            
            result = update_text(content, current_dt, next_dt)
            
            # Verify each transition
            self.assertIn(f'ANALYSIS_YEAR = {next_year}', result, 
                         f"Failed year update for {MONTHS[current_month-1]} -> {MONTHS[next_month-1]}")
            self.assertIn(f'ANALYSIS_MONTH = {next_month}', result,
                         f"Failed month update for {MONTHS[current_month-1]} -> {MONTHS[next_month-1]}")
            self.assertIn(f'MONTH_NAME = "{MONTHS[next_month-1]}"', result,
                         f"Failed name update for {MONTHS[current_month-1]} -> {MONTHS[next_month-1]}")
    
    def test_preserve_other_content(self):
        """Test that non-date content is preserved."""
        content = '''# Some other configuration
DEBUG_MODE = True
DATA_PATH = "../../data/nvd.jsonl"

# ===== DATE CONFIGURATION =====
ANALYSIS_YEAR = 2025
ANALYSIS_MONTH = 6
MONTH_NAME = "June"

# More content
def some_function():
    return "unchanged"
'''
        
        june_dt = datetime(2025, 6, 1)
        july_dt = datetime(2025, 7, 1)
        
        result = update_text(content, june_dt, july_dt)
        
        # Verify other content is preserved
        self.assertIn('DEBUG_MODE = True', result)
        self.assertIn('DATA_PATH = "../../data/nvd.jsonl"', result)
        self.assertIn('def some_function():', result)
        self.assertIn('return "unchanged"', result)
        
        # Verify date updates
        self.assertIn('ANALYSIS_MONTH = 7', result)
        self.assertIn('MONTH_NAME = "July"', result)

def create_test_notebook_file():
    """Create a test notebook file to validate the complete workflow."""
    test_content = '''<VSCode.Cell id="test1" language="markdown">
# About This Notebook
This notebook analyzes CVE data for the selected month.
</VSCode.Cell>
<VSCode.Cell id="test2" language="markdown">
## June 2025 CVE Data
</VSCode.Cell>
<VSCode.Cell id="test3" language="python">
# ===== DATE CONFIGURATION =====
# UPDATE THESE VALUES WHEN CREATING NEW MONTHLY NOTEBOOKS
ANALYSIS_YEAR = 2025
ANALYSIS_MONTH = 6  # June = 6
MONTH_NAME = "June"

# ===== IMPORTS AND SETUP =====
from datetime import date
import pandas as pd

print(f"Analyzing {MONTH_NAME} {ANALYSIS_YEAR}")
</VSCode.Cell>'''
    
    test_dir = "/tmp/test_notebook"
    os.makedirs(test_dir, exist_ok=True)
    
    test_file = os.path.join(test_dir, "June.ipynb")
    with open(test_file, 'w') as f:
        f.write(test_content)
    
    print(f"Created test notebook: {test_file}")
    return test_file

def run_integration_test():
    """Run an integration test with a real notebook file."""
    print("Running integration test...")
    
    # Create test notebook
    test_file = create_test_notebook_file()
    
    try:
        # Read original content
        with open(test_file, 'r') as f:
            original_content = f.read()
        
        print("Original content:")
        print(original_content[:200] + "...")
        
        # Update June -> July
        june_dt = datetime(2025, 6, 1)
        july_dt = datetime(2025, 7, 1)
        
        updated_content = update_text(original_content, june_dt, july_dt)
        
        # Write updated content
        updated_file = test_file.replace("June.ipynb", "July.ipynb")
        with open(updated_file, 'w') as f:
            f.write(updated_content)
        
        print(f"\nCreated updated notebook: {updated_file}")
        
        # Verify changes
        print("\nUpdated content preview:")
        print(updated_content[:400] + "...")
        
        # Check for expected changes
        assert 'ANALYSIS_MONTH = 7' in updated_content
        assert 'MONTH_NAME = "July"' in updated_content
        assert '## July 2025 CVE Data' in updated_content
        assert 'June' not in updated_content.replace('# June = 6', '')  # Allow comment
        
        print("\n✅ Integration test passed!")
        
    except Exception as e:
        print(f"\n❌ Integration test failed: {e}")
        raise
    finally:
        # Cleanup
        if os.path.exists(test_file):
            os.remove(test_file)
        updated_file = test_file.replace("June.ipynb", "July.ipynb")
        if os.path.exists(updated_file):
            os.remove(updated_file)

if __name__ == '__main__':
    print("Testing auto-update functionality...")
    
    # Run unit tests
    print("\n" + "="*50)
    print("RUNNING UNIT TESTS")
    print("="*50)
    
    unittest.main(argv=[''], exit=False, verbosity=2)
    
    # Run integration test
    print("\n" + "="*50)
    print("RUNNING INTEGRATION TEST")
    print("="*50)
    
    run_integration_test()
    
    print("\n" + "="*50)
    print("ALL TESTS COMPLETED")
    print("="*50)
