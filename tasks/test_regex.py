import re
from datetime import datetime, timedelta

# Test the May to June conversion
last_month = datetime(2025, 5, 1)  # May
this_month = datetime(2025, 6, 1)  # June
next_month = (this_month.replace(day=28) + timedelta(days=4)).replace(day=1)

content = """startdate = pd.Timestamp('2025-05-01')
enddate = pd.Timestamp('2025-06-01')
startdate = date(2025, 5, 1)
enddate  = date(2025, 6, 1)"""

print('Original:')
print(content)
print()

# Test specific pd.Timestamp patterns
pattern1 = rf"startdate = pd\.Timestamp\('{last_month.year}-{last_month.month:02d}-01'\)"
replacement1 = f"startdate = pd.Timestamp('{this_month.year}-{this_month.month:02d}-01')"
print(f'Pattern 1: {pattern1} -> {replacement1}')
content = re.sub(pattern1, replacement1, content)
print('After first replacement:')
print(content)
print()

pattern2 = rf"enddate = pd\.Timestamp\('{this_month.year}-{this_month.month:02d}-01'\)"
replacement2 = f"enddate = pd.Timestamp('{next_month.year}-{next_month.month:02d}-01')"
print(f'Pattern 2: {pattern2} -> {replacement2}')
content = re.sub(pattern2, replacement2, content)
print('After second replacement:')
print(content)
print()

# Test specific date() patterns
pattern3 = rf"startdate = date\({last_month.year}, {last_month.month}, 1\)"
replacement3 = f"startdate = date({this_month.year}, {this_month.month}, 1)"
print(f'Pattern 3: {pattern3} -> {replacement3}')
content = re.sub(pattern3, replacement3, content)
print('After third replacement:')
print(content)
print()

pattern4 = rf"enddate\s*=\s*date\({this_month.year}, {this_month.month}, 1\)"
replacement4 = f"enddate  = date({next_month.year}, {next_month.month}, 1)"
print(f'Pattern 4: {pattern4} -> {replacement4}')
content = re.sub(pattern4, replacement4, content)
print('After fourth replacement:')
print(content)
