from core.exceptions.base import BaseException

# Test Custom Exceptions

class TestError(BaseException):
    status_code = 500
    default_detail = 'The test had an Error'
    default_code = 'test_error'
