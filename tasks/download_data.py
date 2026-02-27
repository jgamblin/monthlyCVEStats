import os
import sys
import requests

def format_size(num_bytes):
    """Format bytes into a human-readable string."""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if abs(num_bytes) < 1024:
            return f"{num_bytes:.1f} {unit}"
        num_bytes /= 1024
    return f"{num_bytes:.1f} TB"

def download_nvd_jsonl(data_dir='data', url='https://nvd.handsonhacking.org/nvd.jsonl'):
    os.makedirs(data_dir, exist_ok=True)
    dest_path = os.path.join(data_dir, 'nvd.jsonl')
    temp_path = dest_path + '.partial'

    headers = {}
    downloaded = 0

    # Resume support: if a partial file exists, request from where we left off
    if os.path.exists(temp_path):
        downloaded = os.path.getsize(temp_path)
        headers['Range'] = f'bytes={downloaded}-'
        print(f"Resuming download from {format_size(downloaded)}...")

    print(f"Downloading {url} to {dest_path} ...")
    response = requests.get(url, stream=True, headers=headers, timeout=(10, 30))
    response.raise_for_status()

    total_size = int(response.headers.get('content-length', 0)) + downloaded
    chunk_size = 1024 * 1024  # 1 MB chunks for better throughput

    mode = 'ab' if downloaded > 0 and response.status_code == 206 else 'wb'
    if mode == 'wb':
        downloaded = 0  # Server didn't support range, restart

    print(f"Total size: {format_size(total_size)}")

    with open(temp_path, mode) as f:
        for chunk in response.iter_content(chunk_size=chunk_size):
            f.write(chunk)
            downloaded += len(chunk)
            if total_size > 0:
                pct = downloaded / total_size * 100
                bar_len = 40
                filled = int(bar_len * downloaded // total_size)
                bar = '█' * filled + '░' * (bar_len - filled)
                sys.stdout.write(f"\r  {bar} {pct:5.1f}% ({format_size(downloaded)} / {format_size(total_size)})")
                sys.stdout.flush()

    print()  # newline after progress bar

    # Rename temp file to final destination
    if os.path.exists(dest_path):
        os.remove(dest_path)
    os.rename(temp_path, dest_path)
    print(f"Download complete: {format_size(os.path.getsize(dest_path))}")

if __name__ == '__main__':
    download_nvd_jsonl()