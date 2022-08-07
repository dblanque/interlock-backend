from core.exceptions.base import BaseException

# OU Custom Exceptions

class OUCreate(BaseException):
    status_code = 500
    default_detail = 'Unable to create Organizational Unit'
    default_code = 'ou_create_error'
class MissingField(BaseException):
    status_code = 500
    default_detail = 'A field for the Organizational Unit is missing'
    default_code = 'ou_field_error'
