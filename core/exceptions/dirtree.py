from core.exceptions.base import CoreException
from rest_framework import status

# Dirtree Custom Exceptions


class DirtreeFilterBad(CoreException):
	status_code = status.HTTP_400_BAD_REQUEST
	default_detail = "Error processing Dirtree Filter Dictionary"
	default_code = "dirtree_filt_err"


class DirtreeDistinguishedNameConflict(CoreException):
	status_code = status.HTTP_409_CONFLICT
	default_detail = "Relative DN and Absolute DN cannot be the same"
	default_code = "dirtree_dn_conflict"


class DirtreeMove(CoreException):
	status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
	default_detail = "LDAP Object could not be moved"
	default_code = "dirtree_move_error"


class DirtreeRename(CoreException):
	status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
	default_detail = "LDAP Object could not be renamed"
	default_code = "dirtree_rename_error"


class DirtreeNewNameIsOld(CoreException):
	status_code = status.HTTP_400_BAD_REQUEST
	default_detail = "LDAP Object name has not changed"
	default_code = "dirtree_name_not_changed"
