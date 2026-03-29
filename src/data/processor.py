"""Process and analyze CVE data."""

import json
import logging
from pathlib import Path
from datetime import datetime
from typing import Iterator, Optional, List, Dict, Any
import pandas as pd


class DataProcessor:
    """Process raw NVD data for analysis."""

    def __init__(self, data_file: Path):
        """Initialize processor.
        
        Args:
            data_file: Path to NVD jsonl data file
        """
        self.data_file = Path(data_file)
        self.logger = logging.getLogger(__name__)

    def read_cves(self) -> Iterator[dict]:
        """Read and yield individual CVE records from jsonl file.
        
        The NVD data file contains one line with a JSON array of all CVEs.
        This method yields individual CVE objects from that array.
        
        Yields:
            Dictionary containing individual CVE record
        """
        if not self.data_file.exists():
            self.logger.error(f"Data file not found: {self.data_file}")
            return

        try:
            with open(self.data_file, "r") as f:
                # NVD data is a single JSON array on one line
                data = json.load(f)
                
                if not isinstance(data, list):
                    self.logger.error(f"Expected list of CVEs, got {type(data)}")
                    return
                
                self.logger.info(f"Loaded {len(data)} CVE records from file")
                
                for cve in data:
                    yield cve
                    
        except json.JSONDecodeError as e:
            self.logger.error(f"Invalid JSON in data file: {e}")
        except IOError as e:
            self.logger.error(f"Error reading data file: {e}")

    def _flatten_cve(self, cve: dict) -> dict:
        """Flatten nested CVE structure into flat dictionary.
        
        Args:
            cve: CVE record with nested structure
            
        Returns:
            Flattened dictionary suitable for DataFrame
        """
        flat = {}
        
        # Extract from nested cve object
        if "cve" in cve:
            cve_obj = cve["cve"]
            flat["cve_id"] = cve_obj.get("id")
            flat["published"] = cve_obj.get("published")
            flat["last_modified"] = cve_obj.get("lastModified")
            flat["vuln_status"] = cve_obj.get("vulnStatus")
        
        # Extract CVSS v3 score if available
        if "cve" in cve and "metrics" in cve["cve"]:
            metrics = cve["cve"]["metrics"]
            if "cvssMetricV31" in metrics and metrics["cvssMetricV31"]:
                cvss_data = metrics["cvssMetricV31"][0]
                if "cvssData" in cvss_data:
                    flat["cvss_v3_score"] = cvss_data["cvssData"].get("baseScore")
                    flat["cvss_v3_vector"] = cvss_data["cvssData"].get("vectorString")
            elif "cvssMetricV30" in metrics and metrics["cvssMetricV30"]:
                cvss_data = metrics["cvssMetricV30"][0]
                if "cvssData" in cvss_data:
                    flat["cvss_v3_score"] = cvss_data["cvssData"].get("baseScore")
                    flat["cvss_v3_vector"] = cvss_data["cvssData"].get("vectorString")
        
        # Extract CNA
        if "cve" in cve:
            cve_obj = cve["cve"]
            flat["source_identifier"] = cve_obj.get("sourceIdentifier")
        
        # Extract weakness info
        if "cve" in cve and "weaknesses" in cve["cve"]:
            weaknesses = cve["cve"].get("weaknesses", [])
            if weaknesses:
                # Get first CWE
                for weakness in weaknesses:
                    if "description" in weakness:
                        for desc in weakness["description"]:
                            if "value" in desc:
                                flat["primary_cwe"] = desc["value"]
                                break
                        if "primary_cwe" in flat:
                            break
        
        return flat

    def load_to_dataframe(self, year: Optional[int] = None,
                          month: Optional[int] = None) -> pd.DataFrame:
        """Load CVE data into pandas DataFrame, optionally filtered by date.
        
        Args:
            year: Filter to specific year (optional)
            month: Filter to specific month (optional, requires year)
            
        Returns:
            DataFrame with CVE records
        """
        records = []
        
        for cve in self.read_cves():
            flat_record = self._flatten_cve(cve)
            if flat_record:
                records.append(flat_record)

        if not records:
            self.logger.warning("No records found in data file")
            return pd.DataFrame()

        df = pd.DataFrame(records)
        self.logger.info(f"Created DataFrame with {len(df)} records")

        # Convert published date to datetime
        if "published" in df.columns:
            df["published"] = pd.to_datetime(df["published"], errors="coerce")

        # Filter by date if specified
        if year is not None:
            df = self._filter_by_date(df, year, month)

        return df

    def _filter_by_date(self, df: pd.DataFrame, year: int,
                       month: Optional[int] = None) -> pd.DataFrame:
        """Filter DataFrame by publication date.
        
        Args:
            df: Input DataFrame
            year: Year to filter
            month: Month to filter (optional)
            
        Returns:
            Filtered DataFrame
        """
        if "published" not in df.columns:
            self.logger.warning("No 'published' column found in data")
            return df

        try:
            # Ensure published is datetime
            if not pd.api.types.is_datetime64_any_dtype(df["published"]):
                df["published"] = pd.to_datetime(df["published"], errors="coerce")
            
            # Filter by year
            df = df[df["published"].dt.year == year]
            
            if month is not None:
                df = df[df["published"].dt.month == month]
            
            self.logger.info(f"Filtered to {len(df)} records for {year}-{month or 'all'}")
            return df
            
        except Exception as e:
            self.logger.error(f"Error filtering by date: {e}")
            return df

    def calculate_statistics(self, df: pd.DataFrame) -> dict:
        """Calculate basic statistics from CVE data.
        
        Args:
            df: CVE DataFrame
            
        Returns:
            Dictionary of statistics
        """
        if df.empty:
            return {}

        stats = {
            "total_cves": len(df),
        }

        # Date range
        if "published" in df.columns:
            valid_dates = df["published"].dropna()
            if len(valid_dates) > 0:
                stats["date_range"] = {
                    "start": str(valid_dates.min().date()),
                    "end": str(valid_dates.max().date()),
                }

        # CVSS statistics if available
        if "cvss_v3_score" in df.columns:
            cvss_data = pd.to_numeric(df["cvss_v3_score"], errors="coerce").dropna()
            if len(cvss_data) > 0:
                stats["cvss"] = {
                    "mean": float(cvss_data.mean()),
                    "median": float(cvss_data.median()),
                    "min": float(cvss_data.min()),
                    "max": float(cvss_data.max()),
                }

        return stats
