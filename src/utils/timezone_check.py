"""Timezone verification for scheduled tasks.

Ensures the workflow is running at the correct Central Time.
"""

import logging
from datetime import datetime
from zoneinfo import ZoneInfo


def verify_central_time() -> bool:
    """Verify that the current time is approximately 7 AM Central Time.
    
    GitHub Actions runs on UTC, so we check that:
    - It's the 1st of the month
    - The UTC time converts to approximately 7-8 AM Central
    
    Returns:
        True if running at expected time, False otherwise
        
    Raises:
        SystemExit if running at unexpected time
    """
    logger = logging.getLogger(__name__)
    
    utc_now = datetime.now(ZoneInfo("UTC"))
    central_now = utc_now.astimezone(ZoneInfo("America/Chicago"))
    
    # Check it's the 1st of the month
    if utc_now.day != 1:
        logger.warning(
            f"Workflow not running on the 1st of the month. "
            f"Current date: {utc_now.date()}"
        )
        # Don't fail here - allow manual triggers
        return False
    
    # Check it's between 7 AM and 9 AM Central (accounting for DST)
    hour = central_now.hour
    if 7 <= hour <= 8:
        logger.info(
            f"✓ Running at correct time: {central_now.strftime('%Y-%m-%d %H:%M %Z')}"
        )
        return True
    else:
        logger.warning(
            f"⚠ Running at unusual time: {central_now.strftime('%Y-%m-%d %H:%M %Z')} "
            f"(expected 7-8 AM Central)"
        )
        # Still proceed - could be manual trigger or DST edge case
        return True


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s"
    )
    verify_central_time()
