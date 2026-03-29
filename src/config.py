"""Configuration management for CVE statistics."""

import os
from pathlib import Path
from datetime import datetime
from typing import Optional


class Config:
    """Central configuration for the application."""

    # Paths
    PROJECT_ROOT = Path(__file__).parent.parent
    DATA_DIR = PROJECT_ROOT / "data"
    OUTPUT_DIR = PROJECT_ROOT / "outputs"
    CACHE_DIR = DATA_DIR / "cache"
    NOTEBOOKS_DIR = PROJECT_ROOT / "notebooks"

    # NVD Data
    NVD_DATA_FILE = DATA_DIR / "nvd.jsonl"
    NVD_SOURCE_URL = os.getenv(
        "NVD_SOURCE_URL",
        "https://nvd.handsonhacking.org/nvd.jsonl"
    )
    DOWNLOAD_CHUNK_SIZE = 1024 * 1024  # 1 MB chunks

    # Analysis
    ANALYSIS_YEAR: Optional[int] = None
    ANALYSIS_MONTH: Optional[int] = None

    # Output formats
    REPORT_FORMATS = ["markdown", "json"]
    IMAGE_FORMATS = ["png"]

    # Logging
    LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
    LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"

    # GitHub Actions
    IS_CI = os.getenv("CI") == "true"
    GITHUB_ACTIONS = os.getenv("GITHUB_ACTIONS") == "true"

    # Data processing
    ENABLE_CACHE = True
    CACHE_EXPIRY_DAYS = 1  # Refresh cache daily

    @classmethod
    def get_current_month_info(cls) -> tuple[int, int]:
        """Get current year and month for analysis.
        
        Returns:
            Tuple of (year, month)
        """
        now = datetime.now()
        return (now.year, now.month)

    @classmethod
    def get_report_output_dir(cls, year: int, month: Optional[int] = None) -> Path:
        """Get output directory for reports.
        
        Args:
            year: Year for report
            month: Month for report (optional)
            
        Returns:
            Path to output directory
        """
        if month:
            month_name = datetime(year, month, 1).strftime("%B")
            output_path = cls.OUTPUT_DIR / str(year) / month_name
        else:
            output_path = cls.OUTPUT_DIR / str(year)
        
        output_path.mkdir(parents=True, exist_ok=True)
        return output_path

    @classmethod
    def ensure_directories(cls) -> None:
        """Ensure all required directories exist."""
        for directory in [cls.DATA_DIR, cls.OUTPUT_DIR, cls.CACHE_DIR]:
            directory.mkdir(parents=True, exist_ok=True)

    @classmethod
    def to_dict(cls) -> dict:
        """Convert config to dictionary for logging/debugging."""
        return {
            "project_root": str(cls.PROJECT_ROOT),
            "data_dir": str(cls.DATA_DIR),
            "output_dir": str(cls.OUTPUT_DIR),
            "nvd_data_file": str(cls.NVD_DATA_FILE),
            "is_ci": cls.IS_CI,
            "github_actions": cls.GITHUB_ACTIONS,
        }
