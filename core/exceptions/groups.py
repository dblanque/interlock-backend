from core.exceptions.base import CoreException
from rest_framework import status

# Group Custom Exceptions
class GroupDoesNotExist(CoreException):
    status_code = status.HTTP_400_BAD_REQUEST
    default_detail = 'Specified Group does not exist'
    default_code = 'group_does_not_exist'
class GroupCreate(CoreException):
    status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
    default_detail = 'Group could not be Created'
    default_code = 'group_create'
class GroupDelete(CoreException):
    status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
    default_detail = 'Group could not be Deleted'
    default_code = 'group_delete'
class GroupUpdate(CoreException):
    status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
    default_detail = 'Group could not be Updated'
    default_code = 'group_update'
class GroupMembersAdd(CoreException):
    status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
    default_detail = 'Members could not be added to Group'
    default_code = 'group_member_add'
class GroupMembersRemove(CoreException):
    status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
    default_detail = 'Members could not be removed from Group'
    default_code = 'group_member_remove'
class GroupScopeOrTypeMissing(CoreException):
    status_code = status.HTTP_400_BAD_REQUEST
    default_detail = 'Group Scope or Type missing from Request'
    default_code = 'group_scope_or_type'
class GroupDistinguishedNameMissing(CoreException):
    status_code = status.HTTP_400_BAD_REQUEST
    default_detail = 'Group Distinguished Name missing from Request'
    default_code = 'group_dn_missing'
class GroupBuiltinProtect(CoreException):
    status_code = status.HTTP_400_BAD_REQUEST
    default_detail = 'Specified Group cannot be Deleted as it is builtin'
    default_code = 'group_builtin_protect'
class BadMemberSelection(CoreException):
    status_code = status.HTTP_400_BAD_REQUEST
    default_detail = 'The same members are in the Add Member and Remove Member lists'
    default_code = 'group_members_bad'