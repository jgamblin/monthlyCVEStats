"""Tests for configuration module."""

from datetime import datetime
from src.config import Config


def test_get_current_month_info():
    """Test getting current month info."""
    year, month = Config.get_current_month_info()
    now = datetime.now()
    assert year == now.year
    assert month == now.month


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
