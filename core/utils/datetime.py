from datetime import datetime
from django.utils import timezone as tz

def date_str_to_date(string) -> datetime.date:
    """ 
    Takes a date in ISO format and returns its corresponding datetime.date object
    """
    return tz.datetime.strptime(string, "%Y-%m-%d")

def date_str_to_datetime(string) -> datetime:
    return tz.datetime.strptime(string, "%Y-%m-%d %H:%M:%S")
