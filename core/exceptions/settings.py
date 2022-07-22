from rest_framework.exceptions import APIException

# Setting Exceptions
class SettingTypeDoesNotMatch(APIException):
    status_code = 550
    default_detail = 'The Setting Type does not match to the back-end'
    default_code = 'setting_type_malformed'