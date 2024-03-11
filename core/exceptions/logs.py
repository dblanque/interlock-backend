from core.exceptions.base import BaseException
from rest_framework import status

class LogTruncateMinmaxNotFound(BaseException):
    status_code = status.HTTP_400_BAD_REQUEST
    default_detail = 'Minimum or Maximum truncate values not in request'
    default_code = 'log_trunc_minmax'