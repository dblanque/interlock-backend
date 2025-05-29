import pytest
from datetime import datetime, date, timezone
from django.utils import timezone as tz
from core.utils.datetime import iso_str_to_date, iso_str_to_datetime
tz_utc = timezone.utc

@pytest.mark.parametrize("date_str, expected", [
    # Valid date strings
    ("2023-12-31", date(2023, 12, 31)),
    ("2000-02-29", date(2000, 2, 29)),  # Leap year
    ("0001-01-01", date(1, 1, 1)),      # Minimum date
    # With ignored suffixes
    ("2023-12-31Z", date(2023, 12, 31)),
    ("2023-12-31+05:30", date(2023, 12, 31)),
    ("2023-12-31T23:59:59", date(2023, 12, 31)),
])
def test_iso_str_to_date_valid(date_str, expected):
    assert iso_str_to_date(date_str) == expected

@pytest.mark.parametrize(
	"invalid_date",
    [
		"2023-13-01",       # Invalid month
		"2023-12-32",       # Invalid day
		"2023/12/31",       # Wrong separator
		"not-a-date",       # Garbage string
		"",                 # Empty string
		"2023-12",          # Missing day
	]
)
def test_iso_str_to_date_invalid(invalid_date):
    with pytest.raises(ValueError):
        iso_str_to_date(invalid_date)

@pytest.mark.parametrize(
	"dt_str, expected",
	[
		# Timezone-aware inputs
		("2023-12-31T23:59:59Z", 
		tz.make_aware(datetime(2023, 12, 31, 23, 59, 59), tz_utc)),
		("2023-12-31 23:59:59+05:30",
		tz.make_aware(datetime(2023, 12, 31, 23, 59, 59), 
					tz.get_fixed_timezone(330))),  # +5:30 offset in minutes
		("2023-12-31T00:00:00-08:00", 
		tz.make_aware(datetime(2023, 12, 31, 0, 0), 
					tz.get_fixed_timezone(-480))),  # -8:00 offset
		# Timezone-naive inputs (uses Django's default timezone)
		("2023-12-31 23:59:59", 
		tz.make_aware(datetime(2023, 12, 31, 23, 59, 59))),  # No tzinfo parameter
		# With subseconds
		("2023-12-31T23:59:59.123Z", 
		tz.make_aware(datetime(2023, 12, 31, 23, 59, 59, 123000), tz_utc)),
	],
	ids=[
        "UTC date with Z identifier",
        "+5:30 offset in minutes",
        "-8:00 offset",
        "No tzinfo parameter",
        "With subseconds",
	]
)
def test_iso_str_to_datetime_valid(dt_str, expected):
    result = iso_str_to_datetime(dt_str)
    assert result == expected
    assert result.tzinfo is not None  # Always timezone-aware

@pytest.mark.parametrize("invalid_dt", [
    "2023-12-31T25:00:00",          # Invalid hour
    "2023-12-31T00:00:00+99:99",    # Invalid offset
    "2023-12-31 23:59:59+05:30Z",  # Multiple timezone markers
    "not-a-datetime",
    "",
])
def test_iso_str_to_datetime_invalid(invalid_dt):
    with pytest.raises(ValueError):
        iso_str_to_datetime(invalid_dt)

# Edge Case: Django's default timezone behavior
@pytest.mark.django_db
def test_iso_str_to_datetime_default_timezone(settings):
    settings.TIME_ZONE = "Asia/Tokyo"  # UTC+9
    dt = iso_str_to_datetime("2023-12-31 23:59:59")
    assert dt.tzinfo.key == "Asia/Tokyo"
    assert dt.isoformat() == "2023-12-31T23:59:59+09:00"
