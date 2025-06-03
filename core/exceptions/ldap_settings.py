from core.exceptions.base import CoreException
from rest_framework import status


# Setting Exceptions
class SettingTypeDoesNotMatch(CoreException):
	status_code = status.HTTP_400_BAD_REQUEST
	default_detail = "The Setting Type does not match with the back-end data"
	default_code = "setting_type_malformed"

class SettingChoiceIsInvalid(CoreException):
	status_code = status.HTTP_400_BAD_REQUEST
	default_detail = "The Setting Value is not within valid selectable choices"
	default_code = "setting_choice_invalid"


class SettingNotInList(CoreException):
	status_code = status.HTTP_400_BAD_REQUEST
	default_detail = "The Requested Setting is not in the current search list"
	default_code = "setting_not_in_list"


class SettingLogMaxLimit(CoreException):
	status_code = status.HTTP_400_BAD_REQUEST
	default_detail = "You cannot save more than 10000 logs"
	default_code = "setting_max_log"


class SettingResetFail(CoreException):
	status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
	default_detail = "Could not reset settings to defaults"
	default_code = "setting_reset_fail"


class SettingPresetNotExists(CoreException):
	status_code = status.HTTP_400_BAD_REQUEST
	default_detail = "Settings Preset does not Exist"
	default_code = "setting_preset_not_exists"


class SettingPresetExists(CoreException):
	status_code = status.HTTP_409_CONFLICT
	default_detail = "Settings Preset Already Exists"
	default_code = "setting_preset_exists"


class SettingSerializerError(CoreException):
	status_code = status.HTTP_400_BAD_REQUEST
	default_detail = "Settings Serializer Error"
	default_code = "settings_serializer_error"


class SettingPresetSerializerError(CoreException):
	status_code = status.HTTP_400_BAD_REQUEST
	default_detail = "Settings Preset Serializer Error"
	default_code = "settings_preset_serializer_error"


class SettingPresetMustBeDisabled(CoreException):
	status_code = status.HTTP_400_BAD_REQUEST
	default_detail = "Settings Preset must be Disabled"
	default_code = "settings_preset_must_be_disabled"
