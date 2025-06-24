import pytest
from datetime import datetime, timezone, timedelta
from core.utils.filetime import from_datetime, to_datetime  # Update import path

# Constants for test readability
EPOCH_UTC = datetime(1970, 1, 1, tzinfo=timezone.utc)
PRE_EPOCH = datetime(1969, 7, 20, 20, 17, tzinfo=timezone.utc)  # Moon landing
FAR_FUTURE = datetime(2100, 1, 1, tzinfo=timezone.utc)
LEAP_YEAR = datetime(
	2024, 2, 29, 12, 0, 0, tzinfo=timezone.utc
)  # Valid leap date
WINDOWS_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)
KNOWN_VALUES = [
	(WINDOWS_EPOCH, 0),
	(EPOCH_UTC, 116444736000000000),
	(
		datetime(2023, 1, 1, tzinfo=timezone.utc),
		133170048000000000,
	),  # CORRECTED
	(
		datetime(1999, 12, 31, 23, 59, 59, 999999, tzinfo=timezone.utc),
		125911583999999990,
	),  # CORRECTED
]


@pytest.mark.parametrize(
	"dt, expected_filetime",
	KNOWN_VALUES,
	ids=[
		"Windows Epoch (1601-01-01)",
		"Unix Epoch (1970-01-01)",
		"2023 New Year",
		"Millennium Eve",
	],
)
def test_from_datetime_known_values(dt, expected_filetime):
	"""Verify known datetime to filetime conversions"""
	assert from_datetime(dt) == expected_filetime


@pytest.mark.parametrize(
	"filetime, expected_dt",
	[
		(0, WINDOWS_EPOCH.replace(tzinfo=None)),
		(116444736000000000, EPOCH_UTC.replace(tzinfo=None)),
		(133170048000000000, datetime(2023, 1, 1)),
		(125911583999999999, datetime(1999, 12, 31, 23, 59, 59, 999999)),
	],
	ids=[
		"Windows Epoch return",
		"Unix Epoch return",
		"2023 New Year return",
		"Millennium Eve return",
	],
)
def test_to_datetime_known_values(filetime, expected_dt):
	"""Verify known filetime to datetime conversions"""
	assert to_datetime(filetime) == expected_dt


@pytest.mark.parametrize(
	"dt",
	[
		# Naive datetimes (assumed UTC)
		datetime(2023, 1, 1),
		datetime(2023, 1, 1, 12, 30, 45, 500000),
		# Aware datetimes
		datetime(2023, 1, 1, tzinfo=timezone(timedelta(hours=2))),
		datetime(2023, 1, 1, tzinfo=timezone(timedelta(hours=-8))),
		# Edge cases
		PRE_EPOCH,
		FAR_FUTURE,
		LEAP_YEAR,
		datetime(2000, 1, 1, microsecond=123456),
	],
	ids=[
		"Naive date only",
		"Naive with microseconds",
		"UTC+2 timezone",
		"UTC-8 timezone",
		"Pre-unix-epoch",
		"Far future",
		"Leap day",
		"Microsecond precision",
	],
)
def test_round_trip_conversion(dt):
	"""Verify round-trip conversion consistency"""
	filetime = from_datetime(dt)
	result = to_datetime(filetime)

	# For aware datetimes, compare UTC-equivalent naive
	if dt.tzinfo:
		dt_utc = dt.astimezone(timezone.utc).replace(tzinfo=None)
		assert result == dt_utc
	else:
		assert result == dt


def test_timezone_handling():
	"""Verify timezone conversion logic"""
	# Same absolute time, different timezones
	dt_utc = datetime(2023, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
	dt_est = datetime(2023, 1, 1, 7, 0, 0, tzinfo=timezone(timedelta(hours=-5)))

	assert from_datetime(dt_utc) == from_datetime(dt_est)

	# Conversion result should match UTC naive
	result = to_datetime(from_datetime(dt_est))
	assert result == dt_utc.replace(tzinfo=None)


def test_precision_preservation():
	"""Verify microsecond precision is maintained"""
	dt = datetime(2023, 1, 1, 12, 0, 0, 123456)
	assert to_datetime(from_datetime(dt)) == dt


def test_filetime_boundaries():
	"""Test minimum and maximum representable values"""
	# Minimum Windows filetime (January 1, 1601 UTC)
	min_dt = to_datetime(0)
	assert min_dt == datetime(1601, 1, 1)

	# Maximum 64-bit filetime (December 31, 9999)
	max_dt = to_datetime(2650467743999999999)
	assert max_dt == datetime(9999, 12, 31, 23, 59, 59, 999999)


def test_invalid_input():
	"""Verify proper handling of invalid inputs"""
	with pytest.raises(TypeError):
		from_datetime("2023-01-01")  # String instead of datetime

	with pytest.raises(OverflowError):
		to_datetime(-1)  # Negative filetime


def test_near_zero_boundary():
	"""Test smallest valid filetime (0) and invalid negative"""
	# Smallest valid filetime (1601-01-01)
	assert to_datetime(0) == datetime(1601, 1, 1)

	# Test negative boundary
	with pytest.raises(OverflowError):
		to_datetime(-1)

	# Test very large negative
	with pytest.raises(OverflowError):
		to_datetime(-(10**18))
