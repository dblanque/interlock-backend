from core.exceptions.base import BaseException

# Group Custom Exceptions
class GroupExists(BaseException):
    status_code = 409
    default_detail = 'Group already exists'
    default_code = 'group_exists'
class GroupDoesNotExist(BaseException):
    status_code = 400
    default_detail = 'Specified Group does not exist'
    default_code = 'group_does_not_exist'
class GroupCreate(BaseException):
    status_code = 500
    default_detail = 'Group could not be Created'
    default_code = 'group_create'
class GroupDelete(BaseException):
    status_code = 500
    default_detail = 'Group could not be Deleted'
    default_code = 'group_delete'
class GroupUpdate(BaseException):
    status_code = 500
    default_detail = 'Group could not be Updated'
    default_code = 'group_update'
class GroupMembersAdd(BaseException):
    status_code = 500
    default_detail = 'Members could not be added to Group'
    default_code = 'group_member_add'
class GroupMembersRemove(BaseException):
    status_code = 500
    default_detail = 'Members could not be removed from Group'
    default_code = 'group_member_remove'
class GroupScopeOrTypeMissing(BaseException):
    status_code = 400
    default_detail = 'Group Scope or Type missing from Request'
    default_code = 'group_scope_or_type'
class GroupDistinguishedNameMissing(BaseException):
    status_code = 400
    default_detail = 'Group Distinguished Name missing from Request'
    default_code = 'group_dn_missing'
class GroupBuiltinProtect(BaseException):
    status_code = 400
    default_detail = 'Specified Group cannot be Deleted as it is builtin'
    default_code = 'group_builtin_protect'