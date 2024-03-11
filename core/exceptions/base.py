from rest_framework.exceptions import APIException
from rest_framework import status

class BaseException(APIException):
    def __init__(self, data=None):
        super().__init__()
        if data is not None:
            self.set_detail(data)
        else:
            self.detail = {
                "code": self.default_code,
                "detail": self.default_detail
            }

    def set_detail(self, data):
        self.detail = data
        if isinstance(self.detail, dict):
            if 'code' not in self.detail:
                self.detail['code'] = self.default_code
            if 'detail' not in self.detail:
                self.detail['detail'] = self.default_detail

class AccessTokenInvalid(BaseException):
    status_code = status.HTTP_401_UNAUTHORIZED
    default_detail = 'Access Token Invalid'
    default_code = 'access_token_invalid'
class RefreshTokenExpired(BaseException):
    status_code = status.HTTP_401_UNAUTHORIZED
    default_detail = 'Refresh Token Expired'
    default_code = 'refresh_token_expired'
class BadRequest(BaseException):
    status_code = status.HTTP_400_BAD_REQUEST
    default_detail = 'Bad Request'
    default_code = 'bad_request'
class Unauthorized(BaseException):
    status_code = status.HTTP_401_UNAUTHORIZED
    default_detail = 'Unauthorized'
    default_code = 'unauthorized'
class PermissionDenied(BaseException):
    status_code = status.HTTP_403_FORBIDDEN
    default_detail = 'Permission Denied'
    default_code = 'permission_denied'
class NotAcceptable(BaseException):
    status_code = status.HTTP_406_NOT_ACCEPTABLE
    default_detail = 'Not Acceptable'
    default_code = 'not_acceptable'
class MissingDataKey(BaseException):
    status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
    default_detail = 'Missing key in data'
    default_code = 'data_key_missing'
class LDAPServerUnreachable(BaseException):
    status_code = status.HTTP_502_BAD_GATEWAY
    default_detail = 'LDAP Server Unreachable'
    default_code = 'ldap_unreachable'