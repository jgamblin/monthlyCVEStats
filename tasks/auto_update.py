import os
import re
import shutil
from datetime import datetime, timedelta

# Set your base directory
BASE_DIR = "/Users/gamblin/Code/monthlyCVEStats/2025"
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
    # Replace "May 2025" with "June 2025", etc.
    content = re.sub(
        rf"{MONTHS[last_month.month-1]} {last_month.year}",
        f"{MONTHS[this_month.month-1]} {this_month.year}",
        content
    )
    # Replace "2025-05-01" with "2025-06-01", etc.
    content = re.sub(
        rf"{last_month.year}-{last_month.month:02d}-01",
        f"{this_month.year}-{this_month.month:02d}-01",
        content
    )
    # Replace "2025-06-01" (end date) with next month's first day
    next_month = (this_month.replace(day=28) + timedelta(days=4)).replace(day=1)
    content = re.sub(
        rf"{last_month.year}-{last_month.month+1:02d}-01",
        f"{this_month.year}-{this_month.month+1:02d}-01",
        content
    )
    # Replace folder/file names if needed
    content = content.replace(month_folder_name(last_month), month_folder_name(this_month))
    return content

def main():
    last_month, this_month = get_last_and_this_month()
    src_folder = os.path.join(BASE_DIR, month_folder_name(last_month))
    dst_folder = os.path.join(BASE_DIR, month_folder_name(this_month))

    if not os.path.exists(src_folder):
        print(f"Source folder {src_folder} does not exist.")
        print(f"Available folders in {BASE_DIR}:")
        for folder in os.listdir(BASE_DIR):
            print(f" - {folder}")
        print("Please ensure the previous month's folder exists and is named correctly.")
        return

    if os.path.exists(dst_folder):
        print(f"Destination folder {dst_folder} already exists.")
        return

    # Copy the folder
    shutil.copytree(src_folder, dst_folder)

    # Rename notebook file if present (e.g., May.ipynb -> June.ipynb)
    old_nb = os.path.join(dst_folder, f"{month_folder_name(last_month)}.ipynb")
    new_nb = os.path.join(dst_folder, f"{month_folder_name(this_month)}.ipynb")
    if os.path.exists(old_nb):
        os.rename(old_nb, new_nb)

    # Walk through all files in the new folder and update text
    for root, dirs, files in os.walk(dst_folder):
        for fname in files:
            if fname.endswith(('.ipynb', '.md', '.py', '.txt')):
                fpath = os.path.join(root, fname)
                with open(fpath, "r", encoding="utf-8") as f:
                    content = f.read()
                new_content = update_text(content, last_month, this_month)
                with open(fpath, "w", encoding="utf-8") as f:
                    f.write(new_content)
    print(f"Moved {src_folder} to {dst_folder} and updated dates/text.")

    # Run the new notebook
    new_nb = os.path.join(dst_folder, f"{month_folder_name(this_month)}.ipynb")
    if os.path.exists(new_nb):
        print(f"Running notebook: {new_nb}")
        os.system(f"jupyter nbconvert --to notebook --execute --inplace '{new_nb}'")

if __name__ == "__main__":
    main()