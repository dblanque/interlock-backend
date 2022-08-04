from core.exceptions.base import BaseException

# Setting Exceptions
class SettingTypeDoesNotMatch(BaseException):
    status_code = 400
    default_detail = 'The Setting Type does not match with the back-end data'
    default_code = 'setting_type_malformed'