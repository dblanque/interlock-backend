from core.exceptions.base import CoreException
from rest_framework import status

# OU Custom Exceptions

class OUCreate(CoreException):
    status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
    default_detail = 'Unable to create Organizational Unit'
    default_code = 'ou_create_error'
class MissingField(CoreException):
    status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
    default_detail = 'A field for the Organizational Unit is missing'
    default_code = 'ou_field_error'
