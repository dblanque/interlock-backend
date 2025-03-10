from core.exceptions.base import CoreException
from rest_framework import status

# Application Custom Exceptions

class ApplicationGroupExists(CoreException):
    status_code = status.HTTP_409_CONFLICT
    default_detail = 'The Application Group already exists.'
    default_code = 'application_group_exists'

class ApplicationGroupDoesNotExist(CoreException):
    status_code = status.HTTP_404_NOT_FOUND
    default_detail = 'The Application Group does not exist.'
    default_code = 'application_group_does_not_exist'
