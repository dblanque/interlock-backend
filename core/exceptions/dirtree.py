from core.exceptions.base import BaseException

# Dirtree Custom Exceptions

class DirtreeFilterBad(BaseException):
    status_code = 400
    default_detail = 'Error processing Dirtree Filter Dictionary'
    default_code = 'dirtree_filt_err'
