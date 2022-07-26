from core.exceptions.base import BaseException

# LDAP Custom Exceptions

class CouldNotOpenConnection(BaseException):
    status_code = 504
    default_detail = 'Could not bind to LDAP Server'
    default_code = 'ldap_bind_err'
class CouldNotFetchDirtree(BaseException):
    status_code = 504
    default_detail = 'Could fetch Directory Tree from LDAP Server'
    default_code = 'ldap_tree_err'
class PortUnreachable(BaseException):
    status_code = 504
    default_detail = 'LDAP Server Port unreachable'
    default_code = 'ldap_port_err'
class ConnectionTestFailed(BaseException):
    status_code = 400
    default_detail = 'Bind Connection Failed'
    default_code = 'ldap_bind_test_failed'