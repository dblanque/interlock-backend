from rest_framework.exceptions import APIException

# User Exceptions
# Allowed range: 720 - 740
class UserExists(APIException):
    status_code = 550
    default_detail = 'User already exists'
    default_code = 'user_exists'
class UserPermissionError(APIException):
    status_code = 551
    default_detail = 'User permissions in request are malformed'
    default_code = 'user_permission_malformed'
class UserPasswordsDontMatch(APIException):
    status_code = 552
    default_detail = 'User passwords do not match'
    default_code = 'user_passwords_dont_match'
class UserUpdateError(APIException):
    status_code = 553
    default_detail = 'User could not be updated'
    default_code = 'user_update_error'
class UserDoesNotExist(APIException):
    status_code = 554
    default_detail = 'User Distinguished Name does not exist'
    default_code = 'user_dn_does_not_exist'