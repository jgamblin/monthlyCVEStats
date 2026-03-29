"""Generate reports from CVE analysis."""

import json
import logging
from pathlib import Path
from datetime import datetime
from typing import Optional
import pandas as pd


class ReportGenerator:
    """Generate reports in multiple formats."""

    def __init__(self, output_dir: Path):
        """Initialize generator.
        
        Args:
            output_dir: Directory to write reports
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.logger = logging.getLogger(__name__)

    def generate_markdown(
        self,
        title: str,
        data: dict,
        filename: Optional[str] = None,
    ) -> Path:
        """Generate markdown report.
        
        Args:
            title: Report title
            data: Dictionary of data to include
            filename: Output filename (auto-generated if not provided)
            
        Returns:
            Path to generated report
        """
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"report_{timestamp}.md"

        filepath = self.output_dir / filename

        content = f"# {title}\n\n"
        content += f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"

        for section, section_data in data.items():
            content += f"## {section}\n\n"
            if isinstance(section_data, dict):
                for key, value in section_data.items():
                    content += f"- **{key}**: {value}\n"
            elif isinstance(section_data, list):
                for item in section_data:
                    content += f"- {item}\n"
            else:
                content += f"{section_data}\n"
            content += "\n"

        try:
            with open(filepath, "w") as f:
                f.write(content)
            self.logger.info(f"Markdown report written to {filepath}")
            return filepath
        except IOError as e:
            self.logger.error(f"Error writing markdown report: {e}")
            raise

    def generate_json(
        self,
        data: dict,
        filename: Optional[str] = None,
    ) -> Path:
        """Generate JSON report.
        
        Args:
            data: Dictionary of data to include
            filename: Output filename (auto-generated if not provided)
            
        Returns:
            Path to generated report
        """
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"report_{timestamp}.json"

        filepath = self.output_dir / filename

        output_data = {
            "generated_at": datetime.now().isoformat(),
            "data": data,
        }

        try:
            with open(filepath, "w") as f:
                json.dump(output_data, f, indent=2, default=str)
            self.logger.info(f"JSON report written to {filepath}")
            return filepath
        except IOError as e:
            self.logger.error(f"Error writing JSON report: {e}")
            raise

    def generate_csv(
        self,
        df: pd.DataFrame,
        filename: Optional[str] = None,
    ) -> Path:
        """Generate CSV report from DataFrame.
        
        Args:
            df: Data to write
            filename: Output filename (auto-generated if not provided)
            
        Returns:
            Path to generated report
        """
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"report_{timestamp}.csv"

        filepath = self.output_dir / filename

        try:
            df.to_csv(filepath, index=False)
            self.logger.info(f"CSV report written to {filepath}")
            return filepath
        except Exception as e:
            self.logger.error(f"Error writing CSV report: {e}")
            raise
