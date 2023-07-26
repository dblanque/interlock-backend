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
class UserCreate(BaseException):
    status_code = 500
    default_detail = 'User could not be created'
    default_code = 'user_create_error'
class UserBulkInsertCreateError(BaseException):
    status_code = 500
    default_detail = 'A user could not be created'
    default_code = 'user_bulk_create_error'
class UserBulkInsertMappingError(BaseException):
    status_code = 500
    default_detail = 'A required header mapping is invalid or missing'
    default_code = 'user_bulk_mapping_error'
class UserBulkInsertLengthError(BaseException):
    status_code = 500
    default_detail = 'A row does not have the correct field amount or delimitation'
    default_code = 'user_bulk_length_error'
class UserUpdateError(BaseException):
    status_code = 500
    default_detail = 'User could not be updated'
    default_code = 'user_update_error'
class UserFieldValidatorFailed(BaseException):
    status_code = 500
    default_detail = 'User could not be validated'
    default_code = 'user_field_validator_error'
class UserDoesNotExist(BaseException):
    status_code = 400
    default_detail = 'User Distinguished Name does not exist'
    default_code = 'user_dn_does_not_exist'
class UserDNPathException(BaseException):
    status_code = 400
    default_detail = 'User DN Path Parsing Stage Exception'
    default_code = 'user_dn_path_exception'
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
class BadGroupSelection(BaseException):
    status_code = 400
    default_detail = 'The same groups are in the Add to Group and Remove from Group entries'
    default_code = 'user_group_bad'