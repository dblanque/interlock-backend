from calendar import timegm
from datetime import datetime, timezone, timedelta

# Windows filetime constants
EPOCH_AS_FILETIME = 116444736000000000  # January 1, 1970 as filetime
HUNDREDS_OF_NANOSECONDS = 10_000_000    # 10^7 (100 ns per interval)
MICROSECONDS_TO_100NS = 10               # 10 * 100ns = 1μs

def from_datetime(dt: datetime) -> int:
    """
    Converts a datetime to a Windows filetime. 
    
    For timezone-naive datetimes, UTC is assumed.
    For timezone-aware datetimes, conversion to UTC is performed.
    
    Args:
        dt: Input datetime (naive or aware)
    
    Returns:
        Windows filetime as integer
    """
    if not isinstance(dt, datetime):
        raise TypeError("dt must be of type datetime.")
    # Convert to UTC if timezone-aware
    if dt.tzinfo is not None and dt.tzinfo.utcoffset(dt) is not None:
        dt = dt.astimezone(timezone.utc)
    else:
        dt = dt.replace(tzinfo=timezone.utc)
    
    # Calculate seconds since epoch and convert to 100ns intervals
    epoch_seconds = timegm(dt.timetuple())
    filetime = EPOCH_AS_FILETIME + (epoch_seconds * HUNDREDS_OF_NANOSECONDS)
    
    # Add microseconds converted to 100ns intervals
    return filetime + (dt.microsecond * MICROSECONDS_TO_100NS)

def to_datetime(filetime: int) -> datetime:
    """
    Converts a Windows filetime to a UTC-equivalent naive datetime.
    
    Args:
        filetime: Windows filetime as integer
    
    Returns:
        Naive datetime representing UTC time
    """
    if filetime < 0:
        raise OverflowError("filetime must be non-negative")
    # Calculate total 100ns intervals since filetime epoch
    ns100_since_epoch = filetime - EPOCH_AS_FILETIME

    # Separate into seconds and remainder
    seconds, remainder_ns100 = divmod(ns100_since_epoch, HUNDREDS_OF_NANOSECONDS)
    microseconds = remainder_ns100 // MICROSECONDS_TO_100NS

    # Create UTC base datetime and add calculated duration
    utc_epoch = datetime(1970, 1, 1, tzinfo=timezone.utc)
    return (utc_epoch + timedelta(seconds=seconds, microseconds=microseconds)).replace(tzinfo=None)
