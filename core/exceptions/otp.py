from core.exceptions.base import BaseException

# OTP Exceptions
class OTPInvalidCode(BaseException):
    status_code = 400
    default_detail = 'OTP Code is invalid'
    default_code = 'otp_invalid_code'
class OTPInvalidRecoveryCode(BaseException):
    status_code = 400
    default_detail = 'Recovery Code is invalid'
    default_code = 'otp_invalid_recovery_code'
class OTPInvalidData(BaseException):
    status_code = 400
    default_detail = 'OTP Data is invalid'
    default_code = 'otp_invalid_data'
class OTPRequired(BaseException):
    status_code = 400
    default_detail = 'OTP Code Required'
    default_code = 'otp_required'
class OTPNoDeviceRegistered(BaseException):
    status_code = 400
    default_detail = 'No such device registered'
    default_code = 'otp_no_device_registered'