from core.exceptions.base import BaseException

# Setting Exceptions
class SettingTypeDoesNotMatch(BaseException):
    status_code = 400
    default_detail = 'The Setting Type does not match with the back-end data'
    default_code = 'setting_type_malformed'

class SettingNotInList(BaseException):
    status_code = 400
    default_detail = 'The Requested Setting is not in the current search list'
    default_code = 'setting_not_in_list'
