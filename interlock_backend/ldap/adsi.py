################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: interlock_backend.ldap.adsi
# Contains:
# - LDAP Permission Dictionary
# - LDAP Manual Built-In Object Dictionary
# - Important LDAP Query Functions
###############################################################################

#---------------------------------- IMPORTS -----------------------------------#
from core.models.ldap_settings_db import RunningSettings
from typing import Union
import logging

logger = logging.getLogger(__name__)

# LDAP Permission Dictionary - all values are converted to binary with a 32 zero padding
# Items also contain their index position in the 32bit binary string
LDAP_PERMS = {
    "LDAP_UF_SCRIPT" : { 
        "value" : 1,
        "val_bin" : str(bin(1))[2:].zfill(32),
        "index": str(bin(1))[2:].zfill(32).find("1")
        },
    "LDAP_UF_ACCOUNT_DISABLE" : { 
        "value" : 2,
        "val_bin" : str(bin(2))[2:].zfill(32),
        "index": str(bin(2))[2:].zfill(32).find("1")
        },
    "LDAP_UF_HOMEDIR_REQUIRED" : { 
        "value" : 8,
        "val_bin" : str(bin(8))[2:].zfill(32),
        "index": str(bin(8))[2:].zfill(32).find("1")
        },
    "LDAP_UF_LOCKOUT" : { 
        "value" : 16,
        "val_bin" : str(bin(16))[2:].zfill(32),
        "index": str(bin(16))[2:].zfill(32).find("1")
        },
    "LDAP_UF_PASSWD_NOTREQD" : { 
        "value" : 32,
        "val_bin" : str(bin(32))[2:].zfill(32),
        "index": str(bin(32))[2:].zfill(32).find("1")
        },
    "LDAP_UF_PASSWD_CANT_CHANGE" : { 
        "value" : 64,
        "val_bin" : str(bin(64))[2:].zfill(32),
        "index": str(bin(64))[2:].zfill(32).find("1")
        },
    "LDAP_UF_ENCRYPTED_TEXT_PASSWORD_ALLOWED" : { 
        "value" : 128,
        "val_bin" : str(bin(128))[2:].zfill(32),
        "index": str(bin(128))[2:].zfill(32).find("1")
        },
    "LDAP_UF_NORMAL_ACCOUNT" : { 
        "value" : 512,
        "val_bin" : str(bin(512))[2:].zfill(32),
        "index": str(bin(512))[2:].zfill(32).find("1")
        },
    "LDAP_UF_INTERDOMAIN_TRUST_ACCOUNT" : { 
        "value" : 2048,
        "val_bin" : str(bin(2048))[2:].zfill(32),
        "index": str(bin(2048))[2:].zfill(32).find("1")
        },
    "LDAP_UF_WORKSTATION_TRUST_ACCOUNT" : { 
        "value" : 4096,
        "val_bin" : str(bin(4096))[2:].zfill(32),
        "index": str(bin(4096))[2:].zfill(32).find("1")
        },
    "LDAP_UF_SERVER_TRUST_ACCOUNT" : { 
        "value" : 8192,
        "val_bin" : str(bin(8192))[2:].zfill(32),
        "index": str(bin(8192))[2:].zfill(32).find("1")
        },
    "LDAP_UF_DONT_EXPIRE_PASSWD" : { 
        "value" : 65536,
        "val_bin" : str(bin(65536))[2:].zfill(32),
        "index": str(bin(65536))[2:].zfill(32).find("1")
        },
    "LDAP_UF_MNS_LOGON_ACCOUNT" : { 
        "value" : 131072,
        "val_bin" : str(bin(131072))[2:].zfill(32),
        "index": str(bin(131072))[2:].zfill(32).find("1")
        },
    "LDAP_UF_SMARTCARD_REQUIRED" : { 
        "value" : 262144,
        "val_bin" : str(bin(262144))[2:].zfill(32),
        "index": str(bin(262144))[2:].zfill(32).find("1")
        },
    "LDAP_UF_TRUSTED_FOR_DELEGATION" : { 
        "value" : 524288,
        "val_bin" : str(bin(524288))[2:].zfill(32),
        "index": str(bin(524288))[2:].zfill(32).find("1")
        },
    "LDAP_UF_NOT_DELEGATED" : { 
        "value" : 1048576,
        "val_bin" : str(bin(1048576))[2:].zfill(32),
        "index": str(bin(1048576))[2:].zfill(32).find("1")
        },
    "LDAP_UF_USE_DES_KEY_ONLY" : { 
        "value" : 2097152,
        "val_bin" : str(bin(2097152))[2:].zfill(32),
        "index": str(bin(2097152))[2:].zfill(32).find("1")
        },
    "LDAP_UF_DONT_REQUIRE_PREAUTH" : { 
        "value" : 4194304,
        "val_bin" : str(bin(4194304))[2:].zfill(32),
        "index": str(bin(4194304))[2:].zfill(32).find("1")
        },
    "LDAP_UF_PASSWORD_EXPIRED" : { 
        "value" : 8388608,
        "val_bin" : str(bin(8388608))[2:].zfill(32),
        "index": str(bin(8388608))[2:].zfill(32).find("1")
        },
    "LDAP_UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION" : { 
        "value" : 16777216,
        "val_bin" : str(bin(16777216))[2:].zfill(32),
        "index": str(bin(16777216))[2:].zfill(32).find("1")
        },
    "LDAP_UF_NO_AUTH_DATA_REQUIRED" : { 
        "value" : 33554432,
        "val_bin" : str(bin(33554432))[2:].zfill(32),
        "index": str(bin(33554432))[2:].zfill(32).find("1")
        },
    "LDAP_UF_PARTIAL_SECRETS_ACCOUNT" : { 
        "value" : 67108864,
        "val_bin" : str(bin(67108864))[2:].zfill(32),
        "index": str(bin(67108864))[2:].zfill(32).find("1")
        },
}

LDAP_PERM_BIN_BASE = "0"*32

LDAP_BUILTIN_OBJECTS = [
    "Domain Controllers",
    "Computers",
    "Program Data",
    "System",
    "Builtin",
    "ForeignSecurityPrincipals",
    "Users",
    "Managed Service Accounts"
]

def search_filter_add(filter_string, filter_to_add, operator="&", negate=False):
    """ Adds search filter to LDAP Filter string

    ARGUMENTS
    originalFilter: The filter you wish to modify, if empty the function will create a filter
    filterToAdd: The filter string to add
    operator (default is &): The operator (and|or), supports string or literal operator value

    Returns a string.
    """
    if operator == 'or':
        operator = '|'
    if operator == 'and':
        operator = '&'

    if operator == '|' and filter_string.startswith('(!('):
        logger.warn(filter_to_add)
        logger.warn('Changed operator to & since you are comparing to a negation with an or')
        operator = '&'

    if negate == True:
        prefix = "(!("
        suffix = "))"
    else:
        prefix = "("
        suffix = ")"

    if operator != "&" and operator != "|" and filter_string != "":
        raise Exception(f"Invalid Filter Operator {operator}")
    if not filter_string or filter_string == "":
        newFilter = prefix + filter_to_add + suffix
        return newFilter
    newFilter = "(" + operator + filter_string + prefix + filter_to_add + suffix + ")"
    return newFilter

def search_filter_from_dict(filter_dict: dict, operator: str="|", reverse_key=False):
    """
    Valid Operators: | &
    """
    search_filter = ""
    for object_key, object_type in filter_dict.items():
        _ldap_obj_key = object_key
        _ldap_obj_type = object_type
        if reverse_key:
            _ldap_obj_key = object_type
            _ldap_obj_type = object_key
        if type(_ldap_obj_type) == list:
            for o in _ldap_obj_type:
                search_filter = search_filter_add(search_filter, o + "=" + _ldap_obj_key, operator)
        else:
            search_filter = search_filter_add(search_filter, _ldap_obj_type + "=" + _ldap_obj_key, operator)
    return search_filter

def bin_as_str(value):
    casted_int = int(str(value))
    return str(bin(casted_int))[2:].zfill(32)

def bin_as_hex(value):
    casted_bin = int(str(value).lstrip("0"), 2)
    casted_bin = hex(casted_bin)[2:].zfill(4)
    return str("0x" + casted_bin)

def list_perms():
    """ List all the permissions in the LDAP_PERMS constant array/list

    Prints to console.
    """
    for perm in LDAP_PERMS:
        print(perm + " = " + LDAP_PERMS[perm]["val_bin"] + ", " + str(LDAP_PERMS[perm]["index"]))

def parse_permissions_int(raw_user_permissions: int, user_name=None):
    """
    Parses a raw LDAP Permission Integer Bitmap to a list.
    """
    permissions_list = list()
    i = 0

    for n in range(0, 32): # Loop for each bit in 0-32
        i += 1
        if raw_user_permissions[n] == "1": # If permission matches enter for loop to 
                                   # search which one it is in the dictionary
            for perm_name in LDAP_PERMS:
                perm_binary = LDAP_PERMS[perm_name]['val_bin']
                perm_index = LDAP_PERMS[perm_name]['index']
                if perm_index == n:
                    if user_name: logger.debug(f"User: {user_name}")
                    logger.debug(f"Permission Name: {perm_name}")
                    logger.debug(f"Permission Index: {str(perm_index)}")
                    logger.debug(f"Permission Index (From User): {str(n)}")
                    logger.debug(f"Permission Binary Value (From Constant): {perm_binary}")
                    logger.debug(f"Permission Hex Value (From Constant): {bin_as_hex(perm_binary)}")
                    permissions_list.append(perm_name)
    if user_name: logger.debug(f"Permission List ({user_name}): ")
    else: logger.debug("Permission List:")
    logger.debug(permissions_list)
    return permissions_list

# Lists User permissions (LDAP / AD Servers save them as binary)
def list_user_perms(user, perm_search: str = None, user_is_object: bool = True) -> list:
    """
    ### Creates a list of user permissions from raw LDAP Integer Bitmap
    * user: User dict or object.
    * perm_search:  Allows for directly returning a boolean when a specified 
                    permission is found.
    * user_is_object: Whether the user passed is an object or dict.

    Returns list.

    Returns bool if perm_search is used.
    """
    # Cast raw integer user permissions as string
    if user_is_object == True:
        if user.userAccountControl != "[]":
            raw_user_permissions = bin_as_str(user.userAccountControl)
        else: return None
    else:
        if user.userAccountControl != "[]":
            raw_user_permissions = bin_as_str(user['userAccountControl'])
        else: return None

    user_permissions: list = parse_permissions_int(
        raw_user_permissions=raw_user_permissions,
        user_name=str(user[RunningSettings.LDAP_AUTH_USER_FIELDS["username"]])
    )
    if isinstance(perm_search, str):
        return perm_search in user_permissions
    return user_permissions

def calc_permissions(
        permission_list: list, 
        perm_add: Union[list, str] = None, 
        perm_remove: Union[list, str] = None
    ):
    """ 
    ### Calculates permissions INT based on a desired array of Permission String Keys

    * permissionArray: List of Permissions
    * addPerm: Contains permission(s) to add to calculated result
    * removePerm: Contains permission(s) to remove from calculated result

    Returns an integer.
    """
    # TODO Check that this works properly when permission_list is in object/list
    perm_int = 0

    # Add permissions selected in user creation
    for perm in permission_list:
        p_value = int(LDAP_PERMS[perm]['value'])
        perm_int += p_value
        logger.debug(f"Permission Value added (cast to string): {perm} = {str(p_value)}")

    # Add Permissions to list
    if perm_add and isinstance(perm_add, list):
        for perm in perm_add:
            p_value = int(LDAP_PERMS[perm]['value'])
            perm_int += p_value
            logger.debug(f"Permission Value added (cast to string): {perm} = {str(p_value)}")
    elif perm_add:
        p_value = int(LDAP_PERMS[perm_add]['value'])
        perm_int += p_value
        logger.debug(f"Permission Value added (cast to string): {perm} = {str(p_value)}")

    # Remove permissions from list
    if perm_remove and isinstance(perm_remove, list):
        for perm in perm_remove:
            p_value = int(LDAP_PERMS[perm]['value'])
            perm_int -= p_value
            logger.debug(f"Permission Value removed (cast to string): {perm} = {str(p_value)}")
    elif perm_remove:
        p_value = int(LDAP_PERMS[perm_remove]['value'])
        perm_int -= p_value
        logger.debug(f"Permission Value removed (cast to string): {perm} = {str(p_value)}")

    # Final Result Log
    logger.debug(f"calc_permissions - Final User Permissions Value: {str(perm_int)}")

    return int(perm_int)
