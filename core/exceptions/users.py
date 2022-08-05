from core.exceptions.base import BaseException

# User Exceptions
class UserPermissionError(BaseException):
    status_code = 400
    default_detail = 'User permissions in request are malformed'
    default_code = 'user_permission_malformed'
class UserPasswordsDontMatch(BaseException):
    status_code = 400
    default_detail = 'User passwords do not match'
    default_code = 'user_passwords_dont_match'
class UserUpdateError(BaseException):
    status_code = 500
    default_detail = 'User could not be updated'
    default_code = 'user_update_error'
class UserDoesNotExist(BaseException):
    status_code = 400
    default_detail = 'User Distinguished Name does not exist'
    default_code = 'user_dn_does_not_exist'
class CouldNotUnlockUser(BaseException):
    status_code = 500
    default_detail = 'User could not be unlocked'
    default_code = 'user_unlock_error'
class UserCountryUpdateError(BaseException):
    status_code = 500
    default_detail = 'User country could not be updated'
    default_code = 'user_country_error'
class UserGroupsFetchError(BaseException):
    status_code = 500
    default_detail = 'User Group Memberships could not be fetched'
    default_code = 'user_group_fetch_error'
class CannotDeleteUserPrimaryGroup(BaseException):
    status_code = 400
    default_detail = 'Primary Group for User cannot be Deleted, change the Primary Group ID first'
    default_code = 'user_group_primary_err'