import os
import re
import shutil
from datetime import datetime, timedelta

# Set your base directory relative to this script's location
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(SCRIPT_DIR)  # Go up one level from tasks/ to repo root
BASE_DIR = os.path.join(REPO_ROOT, "2025")
MONTHS = [
    "January", "February", "March", "April", "May", "June",
    "July", "August", "September", "October", "November", "December"
]

def get_last_and_this_month():
    today = datetime.today().replace(day=1)
    last_month = today - timedelta(days=1)
    this_month = today
    return last_month, this_month

def month_folder_name(dt):
    return f"{MONTHS[dt.month-1]}"

def update_text(content, last_month, this_month):
    # Debug print to see what months we're working with
    print(f"Debug: last_month = {last_month} (month {last_month.month})")
    print(f"Debug: this_month = {this_month} (month {this_month.month})")
    
    # Handle the new configuration format with simple variable updates
    # Update ANALYSIS_YEAR
    content = re.sub(
        r'ANALYSIS_YEAR = \d{4}',
        f'ANALYSIS_YEAR = {this_month.year}',
        content
    )
    
    # Update ANALYSIS_MONTH
    content = re.sub(
        r'ANALYSIS_MONTH = \d+',
        f'ANALYSIS_MONTH = {this_month.month}',
        content
    )
    
    # Update MONTH_NAME
    content = re.sub(
        r'MONTH_NAME = "[^"]*"',
        f'MONTH_NAME = "{MONTHS[this_month.month-1]}"',
        content
    )
    
    # Update markdown headers
    content = re.sub(
        rf"## {MONTHS[last_month.month-1]} {last_month.year} CVE Data",
        f"## {MONTHS[this_month.month-1]} {this_month.year} CVE Data",
        content
    )
    
    # Legacy format fallbacks for older notebooks
    # Replace "May 2025" with "June 2025", etc.
    content = re.sub(
        rf"{MONTHS[last_month.month-1]} {last_month.year}",
        f"{MONTHS[this_month.month-1]} {this_month.year}",
        content
    )
    
    # Replace legacy pd.Timestamp patterns - be more specific about start/end
    content = re.sub(
        rf"startdate = pd\.Timestamp\('{last_month.year}-{last_month.month:02d}-01'\)",
        f"startdate = pd.Timestamp('{this_month.year}-{this_month.month:02d}-01')",
        content
    )
    
    # Replace legacy date() patterns - be more specific
    content = re.sub(
        rf"startdate = date\({last_month.year}, {last_month.month}, 1\)",
        f"startdate = date({this_month.year}, {this_month.month}, 1)",
        content
    )
    
    # Handle end dates separately - they should point to next month
    next_month = (this_month.replace(day=28) + timedelta(days=4)).replace(day=1)
    
    # Update end date patterns
    content = re.sub(
        rf"enddate = pd\.Timestamp\('{this_month.year}-{this_month.month:02d}-01'\)",
        f"enddate = pd.Timestamp('{next_month.year}-{next_month.month:02d}-01')",
        content
    )
    
    content = re.sub(
        rf"enddate\s*=\s*date\({this_month.year}, {this_month.month}, 1\)",
        f"enddate  = date({next_month.year}, {next_month.month}, 1)",
        content
    )
    
    # Replace folder/file names if needed
    content = content.replace(month_folder_name(last_month), month_folder_name(this_month))
    return content

def find_most_recent_month_folder():
    """Find the most recent month folder that exists."""
    if not os.path.exists(BASE_DIR):
        return None
    
    month_folders = []
    for item in os.listdir(BASE_DIR):
        if os.path.isdir(os.path.join(BASE_DIR, item)) and item in MONTHS:
            month_folders.append(item)
    
    if not month_folders:
        return None
    
    # Sort by month order (January=0, February=1, etc.)
    month_folders.sort(key=lambda x: MONTHS.index(x))
    return month_folders[-1]  # Return the latest month

def main():
    # Find the most recent month folder to use as source
    most_recent_month = find_most_recent_month_folder()
    if not most_recent_month:
        print(f"No month folders found in {BASE_DIR}")
        print(f"Available items in {BASE_DIR}:")
        if os.path.exists(BASE_DIR):
            for folder in os.listdir(BASE_DIR):
                print(f" - {folder}")
        print("Please create a month folder first (e.g., May, June, etc.)")
        return

    # Calculate the next month after the most recent one
    src_month_index = MONTHS.index(most_recent_month)
    next_month_index = (src_month_index + 1) % 12
    next_month_name = MONTHS[next_month_index]
    
    # Handle year rollover
    current_year = datetime.now().year
    if next_month_index < src_month_index:  # Rolled over to next year
        target_year = current_year + 1
    else:
        target_year = current_year

    src_folder = os.path.join(BASE_DIR, most_recent_month)
    dst_folder = os.path.join(BASE_DIR, next_month_name)

    # First check if destination already exists
    if os.path.exists(dst_folder):
        print(f"Destination folder {dst_folder} already exists.")
        return

    print(f"Using {most_recent_month} as source folder to create {next_month_name}")
    
    if not os.path.exists(src_folder):
        print(f"Source folder {src_folder} does not exist.")
        return

    # Copy the folder
    shutil.copytree(src_folder, dst_folder)

    # Rename notebook file if present (e.g., May.ipynb -> June.ipynb)
    old_nb = os.path.join(dst_folder, f"{most_recent_month}.ipynb")
    new_nb = os.path.join(dst_folder, f"{next_month_name}.ipynb")
    if os.path.exists(old_nb):
        os.rename(old_nb, new_nb)

    # Walk through all files in the new folder and update text
    # Create datetime objects for the source and target months
    src_month_dt = datetime(target_year, src_month_index + 1, 1)
    target_month_dt = datetime(target_year, next_month_index + 1, 1)
    
    for root, dirs, files in os.walk(dst_folder):
        for fname in files:
            if fname.endswith(('.ipynb', '.md', '.py', '.txt')):
                fpath = os.path.join(root, fname)
                with open(fpath, "r", encoding="utf-8") as f:
                    content = f.read()
                new_content = update_text(content, src_month_dt, target_month_dt)
                with open(fpath, "w", encoding="utf-8") as f:
                    f.write(new_content)
    print(f"Copied {src_folder} to {dst_folder} and updated dates/text.")

    # Run the new notebook
    new_nb = os.path.join(dst_folder, f"{next_month_name}.ipynb")
    if os.path.exists(new_nb):
        print(f"Running notebook: {new_nb}")
        os.system(f"jupyter nbconvert --to notebook --execute --inplace '{new_nb}'")

if __name__ == "__main__":
    main()