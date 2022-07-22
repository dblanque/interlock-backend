from rest_framework.exceptions import APIException

# LDAP Custom Exceptions

class CouldNotOpenConnection(APIException):
    status_code = 550
    default_detail = 'Could not bind to LDAP Server'
    default_code = 'ldap_bind_err'

class ConnectionTestFailed(APIException):
    status_code = 551
    default_detail = 'Bind Connection Failed'
    default_code = 'ldap_bind_test_failed'