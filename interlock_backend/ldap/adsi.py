# ldap_adsi.py
###############################################################################
# Contains:
# - LDAP Permission Dictionary
# - LDAP Manual Built-In Object Dictionary
# - Important LDAP Query Functions
###############################################################################
# Originally Created by Dylan Blanqué and BR Consulting S.R.L. (2022)

from interlock_backend.ldap.settings_func import SettingsList
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

def addSearchFilter(originalFilter, filterToAdd, operator="&", negate=False):
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

    if operator == '|' and originalFilter.startswith('(!('):
        logger.warn(filterToAdd)
        logger.warn('Changed operator to & since you are comparing to a negation with an or')
        operator = '&'

    if negate == True:
        filterPrefix = "(!("
        filterSuffix = "))"
    else:
        filterPrefix = "("
        filterSuffix = ")"

    if operator != "&" and operator != "|" and originalFilter != "":
        raise Exception
    if not originalFilter or originalFilter == "":
        newFilter = filterPrefix + filterToAdd + filterSuffix
        return newFilter
    newFilter = "(" + operator + originalFilter + filterPrefix + filterToAdd + filterSuffix + ")"
    return newFilter

def buildFilterFromDict(dictArray, operator="|"):
    search_filter = ""
    for key, objectType in dictArray.items():
        search_filter = addSearchFilter(search_filter, objectType + "=" + key, operator)
    return search_filter

def getDefaultFilterFor(type='OU'):
    """
    Valid Types:
    OU - Organizational Unit
    CN - Common Name
    """
    if type.upper() == 'OU':
        defaults = {
            "organizationalUnit" : "objectCategory",
            "top" : "objectCategory",
            "container" : "objectCategory",
            "builtinDomain" : "objectCategory"
        }
    else:
        defaults = {
            "user" : "objectClass",
            "person" : "objectClass",
            "group" : "objectClass",
            "organizationalPerson" : "objectClass",
            "computer" : "objectClass"
        }
    result = buildFilterFromDict(defaults)
    return result

def bin_as_str(value):
    casted_int = int(str(value))
    return str(bin(casted_int))[2:].zfill(32)

def bin_as_hex(value):
    casted_bin = int(str(value).lstrip("0"), 2)
    casted_bin = hex(casted_bin)[2:].zfill(4)
    return str("0x" + casted_bin)

def check_perm_in_list(permission, list):
    if permission in list:
        return True
    else:
        return False

def list_perms():
    """ List all the permissions in the LDAP_PERMS constant array/list

    Prints to console.
    """
    for perm in LDAP_PERMS:
        print(perm + " = " + LDAP_PERMS[perm]["val_bin"] + ", " + str(LDAP_PERMS[perm]["index"]))

# Lists User permissions (LDAP / AD Servers save them as binary)
def list_user_perms(user, permissionToSearch=None, isObject=True):
    # Cast raw integer user permissions as string
    if isObject == True:
        rawUserPerms = bin_as_str(user.userAccountControl)
    else:
        rawUserPerms = bin_as_str(user['userAccountControl'])
    UserPerms = []
    i = 0
    ldap_settings_list = SettingsList()

    authUsernameIdentifier = ldap_settings_list.LDAP_AUTH_USERNAME_IDENTIFIER
    for n in range(0, 32): # Loop for each bit in 0-32
        i += 1
        if rawUserPerms[n] == "1": # If permission matches enter for loop to 
                                   # search which one it is in the dictionary
            for perm_name in LDAP_PERMS:
                perm_binary = LDAP_PERMS[perm_name]['val_bin']
                perm_index = LDAP_PERMS[perm_name]['index']
                if perm_index == n:
                    logger.debug("User: " + str(user[authUsernameIdentifier]))
                    logger.debug("Permission Name: " + perm_name)
                    logger.debug("Permission Index: " + str(perm_index))
                    logger.debug("Permission Index (From User): " + str(n))
                    logger.debug("Permission Binary Value (From Constant): " + perm_binary)
                    logger.debug("Permission Hex Value (From Constant): " + bin_as_hex(perm_binary))
                    UserPerms.append(perm_name)
    logger.debug("Permission List (" + str(user[authUsernameIdentifier]) + "): ")
    logger.debug(UserPerms)
    if isinstance(permissionToSearch, str):
        return check_perm_in_list(permissionToSearch, UserPerms)
    return UserPerms

def calc_permissions(permissionArray, addPerm='', removePerm=''):
    """ Calculates permissions INT based on a desired array of Permission String Keys

    ARGUMENTS

    :permissionArray: Permission List (Array/List)

    :addPerm: (String || List) -- Contains permission(s) to add to calculated result

    :removePerm: (String || List) -- Contains permission(s) to remove from calculated result

    Returns an integer.
    """
    # TODO Check that this works properly when permission_list is in object/list
    userPermissions = 0

    # Add permissions selected in user creation
    for perm in permissionArray:
        permValue = int(LDAP_PERMS[perm]['value'])
        userPermissions += permValue
        logger.debug("Permission Value added (cast to string): " + perm + " = " + str(permValue))

    # Add Permissions to list
    if addPerm and isinstance(addPerm, list):
        for perm in addPerm:
            permValue = int(LDAP_PERMS[perm]['value'])
            userPermissions += permValue
            logger.debug("Permission Value added (cast to string): " + perm + " = " + str(permValue))
    elif addPerm:
        permValue = int(LDAP_PERMS[addPerm]['value'])
        userPermissions += permValue
        logger.debug("Permission Value added (cast to string): " + addPerm + " = " + str(permValue))

    # Remove permissions from list
    if removePerm and isinstance(removePerm, list):
        for perm in removePerm:
            permValue = int(LDAP_PERMS[perm]['value'])
            userPermissions -= permValue
            logger.debug("Permission Value removed (cast to string): " + perm + " = " + str(permValue))
    elif removePerm:
        permValue = int(LDAP_PERMS[removePerm]['value'])
        userPermissions -= permValue
        logger.debug("Permission Value removed (cast to string): " + removePerm + " = " + str(permValue))

    # Final Result Log
    logger.debug("add_permission - Final User Permissions Value: " + str(userPermissions))

    return int(userPermissions)

def getUserObjectFilter(username):
    ldap_settings_list = SettingsList()
    authUsernameIdentifier = ldap_settings_list.LDAP_AUTH_USERNAME_IDENTIFIER
    authObjectClass = ldap_settings_list.LDAP_AUTH_OBJECT_CLASS
    excludeComputerAccounts = ldap_settings_list.EXCLUDE_COMPUTER_ACCOUNTS

    objectClassFilter = "(objectclass=" + authObjectClass + ")"

    # Exclude Computer Accounts if settings allow it
    if excludeComputerAccounts == True:
        objectClassFilter = addSearchFilter(objectClassFilter, "!(objectclass=computer)")

    # Add filter for username
    objectClassFilter = addSearchFilter(
        objectClassFilter,
        authUsernameIdentifier + "=" + username
        )
    return objectClassFilter

def getUserObject(connection, username, attributes=[SettingsList().LDAP_AUTH_USERNAME_IDENTIFIER, 'distinguishedName'], objectClassFilter=None):
    """ Default: Search for the dn from a Username string param.
    
    Can also be used to fetch entire object from that username string or filtered attributes.

    ARGUMENTS

    :connection: LDAP Connection Object

    :username: (String) -- User to be searched

    :attributes: (String || List) -- Attributes to return in entry, default are DN and Username Identifier

    e.g.: sAMAccountName

    :objectClassFilter: (String) -- Default is obtained from settings

    Returns the connection.
    """
    ldap_settings_list = SettingsList()
    if objectClassFilter == None:
        objectClassFilter = getUserObjectFilter(username)

    connection.search(
        ldap_settings_list.LDAP_AUTH_SEARCH_BASE, 
        objectClassFilter, 
        attributes=attributes
    )

    return connection
