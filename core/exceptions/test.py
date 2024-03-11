from core.exceptions.base import BaseException
from rest_framework import status

# Test Custom Exceptions

class TestError(BaseException):
    status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
    default_detail = 'The test had an Error'
    default_code = 'test_error'
