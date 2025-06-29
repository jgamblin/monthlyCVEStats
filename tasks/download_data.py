import os
import requests

def download_nvd_jsonl(data_dir='data', url='https://nvd.handsonhacking.org/nvd.jsonl'):
    os.makedirs(data_dir, exist_ok=True)
    dest_path = os.path.join(data_dir, 'nvd.jsonl')
    print(f"Downloading {url} to {dest_path} ...")
    response = requests.get(url, stream=True)
    response.raise_for_status()
    with open(dest_path, 'wb') as f:
        for chunk in response.iter_content(chunk_size=8192):
            f.write(chunk)
    print("Download complete.")

if __name__ == '__main__':
    download_nvd_jsonl()