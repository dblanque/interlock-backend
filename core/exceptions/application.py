from core.exceptions.base import CoreException
from rest_framework import status

# Application Custom Exceptions

class ApplicationExists(CoreException):
    status_code = status.HTTP_409_CONFLICT
    default_detail = 'The SSO Application already exists.'
    default_code = 'application_exists'
