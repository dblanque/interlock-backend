from datetime import datetime, date
from django.utils import timezone as tz


def iso_str_to_date(s: str) -> date:
	"""
	Converts an ISO date string (YYYY-MM-DD) to datetime.date.
	Ignores any time/timezone suffixes (e.g., "2023-12-31Z" → date(2023, 12, 31)).

	Raises:
		ValueError: For invalid date formats.

	Returns:
		date
	"""
	try:
		return datetime.strptime(s[:10], "%Y-%m-%d").date()
	except ValueError as e:
		raise ValueError(
			f"Invalid date format. Expected YYYY-MM-DD, got: {s[:10]}"
		) from e


def iso_str_to_datetime(s: str) -> datetime:
	"""
	Converts an ISO 8601 datetime string to a timezone-aware datetime.
	- Supports "Z", ±HH:MM, ±HHMM, and no timezone (assumes Django's default).

	Raises:
		ValueError: For invalid date formats.

	Returns:
	            datetime
	"""
	try:
		s = s.replace("Z", "+00:00").replace(
			" ", "T"
		)  # Normalize for Python ≤3.10
		dt = datetime.fromisoformat(s)
		return tz.make_aware(dt) if dt.tzinfo is None else dt
	except ValueError as e:
		raise ValueError(f"Invalid ISO datetime format: {s}") from e
