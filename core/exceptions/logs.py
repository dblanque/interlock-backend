from core.exceptions.base import BaseException

class LogTruncateMinmaxNotFound(BaseException):
    status_code = 504
    default_detail = 'Minimum or Maximum truncate values not in request'
    default_code = 'log_trunc_minmax'