from core.exceptions.base import BaseException

# Dirtree Custom Exceptions

class DirtreeFilterBad(BaseException):
    status_code = 400
    default_detail = 'Error processing Dirtree Filter Dictionary'
    default_code = 'dirtree_filt_err'
class DirtreeDistinguishedNameConflict(BaseException):
    status_code = 409
    default_detail = 'Relative DN and Absolute DN cannot be the same'
    default_code = 'dirtree_dn_conflict'
class DirtreeMove(BaseException):
    status_code = 500
    default_detail = 'LDAP Object could not be moved'
    default_code = 'dirtree_move_error'
class DirtreeNewNameIsOld(BaseException):
    status_code = 400
    default_detail = 'LDAP Object could not be moved'
    default_code = 'dirtree_move_error'
