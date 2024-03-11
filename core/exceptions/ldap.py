from core.exceptions.base import BaseException
from rest_framework import status

# LDAP Custom Exceptions

class LDAPObjectExists(BaseException):
    status_code = status.HTTP_409_CONFLICT
    default_detail = 'An object with this Common Name already exists'
    default_code = 'ldap_obj_exists'
class LDAPConnectionNotOpen(BaseException):
    status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
    default_detail = 'No LDAP Connection was open prior to this operation'
    default_code = 'ldap_connection_not_open'
class LDAPPermissionsInsufficient(BaseException):
    status_code = status.HTTP_400_BAD_REQUEST
    default_detail = 'Insufficient LDAP Permissions'
    default_code = 'ldap_perm_insufficient'
class LDAPObjectDoesNotExist(BaseException):
    status_code = status.HTTP_409_CONFLICT
    default_detail = 'An object with this Distinguished Name does not exist'
    default_code = 'ldap_obj_doesnt_exist'
class CouldNotOpenConnection(BaseException):
    status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    default_detail = 'Could not bind to LDAP Server'
    default_code = 'ldap_bind_err'
class CouldNotFetchDirtree(BaseException):
    status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
    default_detail = 'Could not fetch Directory Tree from LDAP Server'
    default_code = 'ldap_tree_err'
class PortUnreachable(BaseException):
    status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    default_detail = 'LDAP Server Port unreachable'
    default_code = 'ldap_port_err'
class ConnectionTestFailed(BaseException):
    status_code = status.HTTP_400_BAD_REQUEST
    default_detail = 'Bind Connection Failed'
    default_code = 'ldap_bind_test_failed'