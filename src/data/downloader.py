"""Download NVD (National Vulnerability Database) data."""

import logging
import os
from pathlib import Path
from typing import Optional
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


class NVDDownloader:
    """Download and manage NVD data files."""

    def __init__(
        self,
        output_file: Path,
        source_url: str,
        chunk_size: int = 1024 * 1024,  # 1 MB
    ):
        """Initialize downloader.
        
        Args:
            output_file: Path to save downloaded data
            source_url: URL to download from
            chunk_size: Download chunk size in bytes
        """
        self.output_file = Path(output_file)
        self.source_url = source_url
        self.chunk_size = chunk_size
        self.logger = logging.getLogger(__name__)

    def _get_session_with_retries(self, retries: int = 3) -> requests.Session:
        """Create a requests session with retry logic.
        
        Args:
            retries: Number of retries for failed requests
            
        Returns:
            Configured requests.Session
        """
        session = requests.Session()
        retry_strategy = Retry(
            total=retries,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        return session

    def _get_remote_size(self) -> Optional[int]:
        """Get the size of the remote file.
        
        Returns:
            File size in bytes, or None if unable to determine
        """
        try:
            session = self._get_session_with_retries()
            response = session.head(self.source_url, timeout=10, allow_redirects=True)
            response.raise_for_status()
            
            if "content-length" in response.headers:
                return int(response.headers["content-length"])
            return None
        except Exception as e:
            self.logger.warning(f"Could not determine remote file size: {e}")
            return None

    def download(self, resume: bool = True) -> bool:
        """Download NVD data with optional resume support.
        
        Args:
            resume: Whether to resume partial downloads
            
        Returns:
            True if download successful, False otherwise
        """
        self.output_file.parent.mkdir(parents=True, exist_ok=True)

        # Check if file already exists and get its size
        start_byte = 0
        if resume and self.output_file.exists():
            start_byte = self.output_file.stat().st_size
            self.logger.info(f"Resuming download from byte {start_byte}")

        headers = {}
        if resume and start_byte > 0:
            headers["Range"] = f"bytes={start_byte}-"

        try:
            session = self._get_session_with_retries()
            remote_size = self._get_remote_size()
            
            response = session.get(
                self.source_url,
                headers=headers,
                stream=True,
                timeout=30,
            )
            response.raise_for_status()

            total_size = remote_size or int(response.headers.get("content-length", 0))
            downloaded = start_byte

            mode = "ab" if start_byte > 0 else "wb"
            with open(self.output_file, mode) as f:
                for chunk in response.iter_content(chunk_size=self.chunk_size):
                    if chunk:
                        f.write(chunk)
                        downloaded += len(chunk)

                        if total_size > 0:
                            percent = (downloaded / total_size) * 100
                            self.logger.info(
                                f"Downloaded {downloaded:,} / {total_size:,} bytes "
                                f"({percent:.1f}%)"
                            )

            self.logger.info(f"Download complete: {self.output_file}")
            return True

        except requests.RequestException as e:
            self.logger.error(f"Download failed: {e}")
            return False
        except IOError as e:
            self.logger.error(f"File write error: {e}")
            return False

    def verify(self) -> bool:
        """Verify the downloaded file is valid.
        
        Returns:
            True if file exists and is readable
        """
        if not self.output_file.exists():
            self.logger.error(f"File does not exist: {self.output_file}")
            return False

        file_size = self.output_file.stat().st_size
        if file_size == 0:
            self.logger.error("Downloaded file is empty")
            return False

        # Try reading first line to verify it's valid JSON lines format
        try:
            with open(self.output_file, "r") as f:
                first_line = f.readline()
                if first_line.strip():
                    import json
                    json.loads(first_line)
                    self.logger.info(
                        f"✓ File verified ({file_size:,} bytes, "
                        f"readable JSON Lines format)"
                    )
                    return True
        except Exception as e:
            self.logger.error(f"File verification failed: {e}")
            return False

        return False
