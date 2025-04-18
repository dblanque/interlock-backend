from core.exceptions.base import CoreException
from rest_framework import status

# LDAP Custom Exceptions


class LDAPObjectExists(CoreException):
	status_code = status.HTTP_409_CONFLICT
	default_detail = "An object with this Common Name already exists"
	default_code = "ldap_obj_exists"


class LDAPConnectionNotOpen(CoreException):
	status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
	default_detail = "No LDAP Connection was open prior to this operation"
	default_code = "ldap_connection_not_open"


class LDAPPermissionsInsufficient(CoreException):
	status_code = status.HTTP_400_BAD_REQUEST
	default_detail = "Insufficient LDAP Permissions"
	default_code = "ldap_perm_insufficient"


class LDAPObjectDoesNotExist(CoreException):
	status_code = status.HTTP_409_CONFLICT
	default_detail = "An object with this Distinguished Name does not exist"
	default_code = "ldap_obj_doesnt_exist"


class CouldNotOpenConnection(CoreException):
	status_code = status.HTTP_503_SERVICE_UNAVAILABLE
	default_detail = "Could not bind to LDAP Server"
	default_code = "ldap_bind_err"


class CouldNotFetchDirtree(CoreException):
	status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
	default_detail = "Could not fetch Directory Tree from LDAP Server"
	default_code = "ldap_tree_err"


class PortUnreachable(CoreException):
	status_code = status.HTTP_503_SERVICE_UNAVAILABLE
	default_detail = "LDAP Server Port unreachable"
	default_code = "ldap_port_err"


class ConnectionTestFailed(CoreException):
	status_code = status.HTTP_400_BAD_REQUEST
	default_detail = "Bind Connection Failed"
	default_code = "ldap_bind_test_failed"


class DistinguishedNameValidationError(CoreException):
	status_code = status.HTTP_400_BAD_REQUEST
	default_detail = "LDAP Distinguished Name Validation Error"
	default_code = "ldap_dn_validation_error"

class LDIFBadField(CoreException):
	status_code = status.HTTP_400_BAD_REQUEST
	default_detail = "LDIF Field Validation Error"
	default_code = "ldif_bad_field"
