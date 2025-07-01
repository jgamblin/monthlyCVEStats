from datetime import datetime

# Simulate what happens in the script
most_recent_month = "May"
MONTHS = ["January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December"]

src_month_index = MONTHS.index(most_recent_month)  # 4 (May = index 4)
next_month_index = (src_month_index + 1) % 12      # 5 (June = index 5)
target_year = 2025

src_month_dt = datetime(target_year, src_month_index + 1, 1)     # datetime(2025, 5, 1) - May
target_month_dt = datetime(target_year, next_month_index + 1, 1) # datetime(2025, 6, 1) - June

print(f"Source month (May): {src_month_dt}")
print(f"Target month (June): {target_month_dt}")
print(f"Source month number: {src_month_dt.month}")
print(f"Target month number: {target_month_dt.month}")
