from core.exceptions.base import CoreException
from rest_framework import status

# OTP Exceptions
class OTPInvalidCode(CoreException):
    status_code = status.HTTP_400_BAD_REQUEST
    default_detail = 'OTP Code is invalid'
    default_code = 'otp_invalid_code'
class OTPInvalidRecoveryCode(CoreException):
    status_code = status.HTTP_400_BAD_REQUEST
    default_detail = 'Recovery Code is invalid'
    default_code = 'otp_invalid_recovery_code'
class OTPInvalidData(CoreException):
    status_code = status.HTTP_400_BAD_REQUEST
    default_detail = 'OTP Data is invalid'
    default_code = 'otp_invalid_data'
class OTPRequired(CoreException):
    status_code = status.HTTP_400_BAD_REQUEST
    default_detail = 'OTP Code Required'
    default_code = 'otp_required'
class OTPNoDeviceRegistered(CoreException):
    status_code = status.HTTP_400_BAD_REQUEST
    default_detail = 'No such device registered'
    default_code = 'otp_no_device_registered'