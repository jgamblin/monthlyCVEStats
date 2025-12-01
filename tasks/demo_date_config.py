0#!/usr/bin/env python3
"""
Demo script showing how the new date configuration format works.
This makes monthly notebook updates much more reliable.
"""

from datetime import datetime, date
from calendar import monthrange

# ===== DATE CONFIGURATION =====
# These are the only values that need to be updated for each month
ANALYSIS_YEAR = 2025
ANALYSIS_MONTH = 7  # July = 7
MONTH_NAME = "July"

# ===== CALCULATED VALUES =====
# Everything else is calculated automatically from the configuration above

def calculate_date_ranges():
    """Calculate start and end dates based on configuration."""
    
    # Calculate start date (first day of analysis month)
    start_date_str = f"{ANALYSIS_YEAR}-{ANALYSIS_MONTH:02d}-01"
    
    # Calculate end date (first day of next month)
    if ANALYSIS_MONTH == 12:
        end_year = ANALYSIS_YEAR + 1
        end_month = 1
    else:
        end_year = ANALYSIS_YEAR
        end_month = ANALYSIS_MONTH + 1
    end_date_str = f"{end_year}-{end_month:02d}-01"
    
    # Get number of days in the analysis month
    days_in_month = monthrange(ANALYSIS_YEAR, ANALYSIS_MONTH)[1]
    
    return start_date_str, end_date_str, days_in_month

def demo():
    """Demonstrate the date configuration system."""
    print("=== CVE Monthly Analysis Date Configuration Demo ===")
    print(f"Analysis Period: {MONTH_NAME} {ANALYSIS_YEAR}")
    print(f"Configuration: Year={ANALYSIS_YEAR}, Month={ANALYSIS_MONTH}")
    print()
    
    start_date_str, end_date_str, days_in_month = calculate_date_ranges()
    
    print("Calculated values:")
    print(f"  Start Date: {start_date_str}")
    print(f"  End Date: {end_date_str}")
    print(f"  Days in Month: {days_in_month}")
    print()
    
    # Show how this would be used in pandas filtering
    print("Pandas filter example:")
    print(f"  startdate_pd = pd.Timestamp('{start_date_str}')")
    print(f"  enddate_pd = pd.Timestamp('{end_date_str}')")
    print("  nvd = nvd[(nvd['Published'] >= startdate_pd) & (nvd['Published'] < enddate_pd)]")
    print()
    
    print("Benefits of this approach:")
    print("  ✅ Only 3 simple variables need to be updated each month")
    print("  ✅ No complex date string manipulations")
    print("  ✅ Automatic handling of month boundaries and leap years")
    print("  ✅ Clear separation between configuration and logic")
    print("  ✅ Easy for automated scripts to update reliably")

if __name__ == "__main__":
    demo()
