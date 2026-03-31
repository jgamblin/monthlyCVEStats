"""Tests for configuration module."""

from datetime import datetime
from unittest.mock import patch
from src.config import Config


def test_get_current_month_info_mid_month():
    """On any day other than the 1st, return the current month."""
    fake_now = datetime(2026, 4, 15)
    with patch("src.config.datetime") as mock_dt:
        mock_dt.now.return_value = fake_now
        year, month = Config.get_current_month_info()
    assert year == 2026
    assert month == 4


def test_get_current_month_info_first_of_month():
    """On the 1st, return the previous month (report on completed month)."""
    fake_now = datetime(2026, 4, 1)
    with patch("src.config.datetime") as mock_dt:
        mock_dt.now.return_value = fake_now
        year, month = Config.get_current_month_info()
    assert year == 2026
    assert month == 3


def test_get_current_month_info_jan_first():
    """On Jan 1st, return December of the previous year."""
    fake_now = datetime(2026, 1, 1)
    with patch("src.config.datetime") as mock_dt:
        mock_dt.now.return_value = fake_now
        year, month = Config.get_current_month_info()
    assert year == 2025
    assert month == 12


def test_get_report_output_dir_with_month():
    """Test report output directory creation with month."""
    output_dir = Config.get_report_output_dir(2026, 3)
    assert "2026" in str(output_dir)
    assert "March" in str(output_dir)
    assert output_dir.exists()


def test_get_report_output_dir_without_month():
    """Test report output directory creation without month."""
    output_dir = Config.get_report_output_dir(2026)
    assert "2026" in str(output_dir)
    assert output_dir.exists()


def test_ensure_directories():
    """Test that required directories are created."""
    Config.ensure_directories()
    assert Config.DATA_DIR.exists()
    assert Config.OUTPUT_DIR.exists()
    assert Config.CACHE_DIR.exists()


def test_config_to_dict():
    """Test converting config to dictionary."""
    config_dict = Config.to_dict()
    assert "project_root" in config_dict
    assert "data_dir" in config_dict
    assert "output_dir" in config_dict
