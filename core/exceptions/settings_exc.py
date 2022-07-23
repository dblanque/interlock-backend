from core.exceptions.base import BaseException

# Setting Exceptions
class SettingTypeDoesNotMatch(BaseException):
    status_code = 550
    default_detail = 'The Setting Type does not match to the back-end'
    default_code = 'setting_type_malformed'