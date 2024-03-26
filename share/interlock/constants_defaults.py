################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: interlock_backend.ldap.defaults

### LDAP SETTINGS

# If this is set to True then the LDAP Connector will not attempt
# to decrypt your LDAP Bind Password
# ! Not recommended
PLAIN_TEXT_BIND_PASSWORD = False

# The URL of the LDAP server(s).  List multiple servers for high availability ServerPool connection.
# ! Change the prefix to ldaps:// if using TLS
LDAP_AUTH_URL = ["ldap://localhost:389"]

# This variable is used by the Interlock back-end to respond the correct domain info to the Front-end
LDAP_DOMAIN = "example.com"

# Use SSL on connection.
LDAP_AUTH_USE_SSL = False

# Initiate TLS on connection.
LDAP_AUTH_USE_TLS = False

# Specify which TLS version to use (Python 3.10 requires TLSv1 or higher)
import ssl
LDAP_AUTH_TLS_VERSION = ssl.PROTOCOL_TLSv1_2

# The LDAP search base for looking up users.
LDAP_AUTH_SEARCH_BASE = "dc=example,dc=com"

# The Schema Naming Context, you shouldn't need to change this
LDAP_SCHEMA_NAMING_CONTEXT = "CN=Schema,CN=Configuration"

# The LDAP class that represents a user.
LDAP_AUTH_OBJECT_CLASS = "person"

# Whether the DNS Zones are in the Legacy Location
LDAP_DNS_LEGACY = False

# !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! #
# ! Don't change the values below or Group Type/Scope changes will break ! #
# !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! #
# Group Type Value Mapping
LDAP_GROUP_TYPE_MAPPING = {
    # Distribution Group
    0:0,
    # Security Group
    1:-2147483648
}

# Group Scope Value Mapping
LDAP_GROUP_SCOPE_MAPPING = {
    # Global Scope
    0:2,
    # Domain Local Scope
    1:4,
    # Universal Scope
    2:8
}
# !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! #

# Set this to False if you wish to include Computer Accounts in User Listings
EXCLUDE_COMPUTER_ACCOUNTS = True

# Set this if you want to only use the settings in this constants,
# Overrides will stop having an effect on system calls
DISABLE_SETTING_OVERRIDES = False

# Change in OpenLDAP
LDAP_OU_FIELD = 'sAMAccountName'
LDAP_GROUP_FIELD = 'sAMAccountName'

# User model fields mapped to the LDAP
# attributes that represent them.
LDAP_AUTH_USER_FIELDS = {
    "username": "sAMAccountName",
    "first_name": "givenName",
    "last_name": "sn",
    "email": "mail",
    "dn": "distinguishedName"
}

# Normalize to the standard LDAP string if it's sAMAccountName just in case
if str(LDAP_AUTH_USER_FIELDS["username"]).lower() == 'samaccountname':
    LDAP_AUTH_USERNAME_IDENTIFIER = "sAMAccountName"
else:
    LDAP_AUTH_USERNAME_IDENTIFIER = LDAP_AUTH_USER_FIELDS["username"]

# A tuple of django model fields used to uniquely identify a user.
LDAP_AUTH_USER_LOOKUP_FIELDS = (
    "username",
    "email"
)

# Path to a callable that takes a dict of {model_field_name: value},
# returning a dict of clean model data.
# Use this to customize how data loaded from LDAP is saved to the User model.
LDAP_AUTH_CLEAN_USER_DATA = "django_python3_ldap.utils.clean_user_data"

# Path to a callable that takes a user model, a dict of {ldap_field_name: [value]}
# a LDAP connection object (to allow further lookups), and saves any additional
# user relationships based on the LDAP data.
# Use this to customize how data loaded from LDAP is saved to User model relations.
# For customizing non-related User model fields, use LDAP_AUTH_CLEAN_USER_DATA.
LDAP_AUTH_SYNC_USER_RELATIONS = "django_python3_ldap.utils.sync_user_relations"

# Path to a callable that takes a dict of {ldap_field_name: value},
# returning a list of [ldap_search_filter]. The search filters will then be AND'd
# together when creating the final search filter.
LDAP_AUTH_FORMAT_SEARCH_FILTERS = "django_python3_ldap.utils.format_search_filters"

# Path to a callable that takes a dict of {model_field_name: value}, and returns
# a string of the username to bind to the LDAP server.
# Use this to support different types of LDAP server.
LDAP_AUTH_FORMAT_USERNAME = "django_python3_ldap.utils.format_username_active_directory"

# Sets the login domain for Active Directory users.
LDAP_AUTH_ACTIVE_DIRECTORY_DOMAIN = "EXAMPLE"

# The LDAP username and password of a user for querying the LDAP database for user
# details. If None, then the authenticated user will be used for querying, and
# the `ldap_sync_users` command will perform an anonymous query.
# This is used when the local Interlock Admin is logged in.
LDAP_AUTH_CONNECTION_USER_DN = "CN=Administrator,CN=Users,DC=example,DC=com"

LDAP_AUTH_CONNECTION_USERNAME = LDAP_AUTH_CONNECTION_USER_DN.split(',')[0].split('CN=')[1]
LDAP_AUTH_CONNECTION_PASSWORD = None

# Set connection/receive timeouts (in seconds) on the underlying `ldap3` library.
LDAP_AUTH_CONNECT_TIMEOUT = 5
LDAP_AUTH_RECEIVE_TIMEOUT = 5

ADMIN_GROUP_TO_SEARCH = "CN=Administrators,CN=Builtin,DC=example,DC=com"
LDAP_DIRTREE_OU_FILTER = {
    "organizationalUnit" : "objectCategory",
    "top" : "objectCategory",
    "container" : "objectCategory",
    "builtinDomain" : "objectClass"
}

LDAP_DIRTREE_CN_FILTER = {
    "user" : "objectClass",
    "person" : "objectClass",
    "group" : "objectClass",
    "organizationalPerson" : "objectClass",
    "computer" : "objectClass"
}

LDAP_DIRTREE_ATTRIBUTES = [
    # User Attrs
    'givenName', 
    'sn', 
    'displayName',
    'mail',
    'telephoneNumber',
    'streetAddress',
    'postalCode',
    'l', # Local / City
    'st', # State/Province
    'countryCode', # INT
    'co', # 2 Letter Code for Country
    'c', # Full Country Name
    'wWWHomePage',
    'distinguishedName',
    'userPrincipalName',
    'userAccountControl', # Permission ACLs
    'whenCreated',
    'whenChanged',
    'lastLogon',
    'badPwdCount',
    'pwdLastSet',
    'primaryGroupID',
    'objectClass',
    'objectCategory',
    'sAMAccountType',

    # Group Attrs
    'cn',
    'member',
    'distinguishedName',
    'groupType',
    'objectSid'
]

################################## Logging #####################################
LDAP_LOG_READ = False
LDAP_LOG_CREATE = True
LDAP_LOG_UPDATE = True
LDAP_LOG_DELETE = True
LDAP_LOG_OPEN_CONNECTION = False
LDAP_LOG_CLOSE_CONNECTION = False
LDAP_LOG_LOGIN = False
LDAP_LOG_LOGOUT = False
LDAP_LOG_MAX = 100

CMAPS = {
    "LDAP_AUTH_URL":"ldap_uri",
    "LDAP_DOMAIN":"string",
    "LDAP_LOG_MAX":"integer",
    "LDAP_LOG_READ":"boolean",
    "LDAP_LOG_CREATE":"boolean",
    "LDAP_LOG_UPDATE":"boolean",
    "LDAP_LOG_DELETE":"boolean",
    "LDAP_LOG_OPEN_CONNECTION":"boolean",
    "LDAP_LOG_CLOSE_CONNECTION":"boolean",
    "LDAP_LOG_LOGIN":"boolean",
    "LDAP_LOG_LOGOUT":"boolean",
    "LDAP_AUTH_USE_SSL": "boolean", 
    "LDAP_AUTH_USE_TLS": "boolean", 
    "LDAP_AUTH_TLS_VERSION": "select",
    "LDAP_AUTH_SEARCH_BASE":"string",
    "LDAP_DNS_LEGACY": "boolean",
    "LDAP_AUTH_OBJECT_CLASS":"string",
    "EXCLUDE_COMPUTER_ACCOUNTS": "boolean",
    "LDAP_AUTH_USER_FIELDS": "object",
    "LDAP_DIRTREE_OU_FILTER": "object",
    "LDAP_DIRTREE_CN_FILTER": "object",
    "LDAP_AUTH_ACTIVE_DIRECTORY_DOMAIN": "string",
    "LDAP_AUTH_CONNECTION_USER_DN":"string",
    "LDAP_AUTH_CONNECTION_USERNAME":"string",
    "LDAP_AUTH_CONNECTION_PASSWORD": "password",
    "LDAP_AUTH_CONNECT_TIMEOUT": "integer",
    "LDAP_AUTH_RECEIVE_TIMEOUT": "integer",
    "LDAP_AUTH_RECEIVE_TIMEOUT": "integer",
    "ADMIN_GROUP_TO_SEARCH": "string"
}
