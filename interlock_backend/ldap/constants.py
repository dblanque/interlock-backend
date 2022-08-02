### LDAP SETTINGS

# The URL of the LDAP server(s).  List multiple servers for high availability ServerPool connection.
LDAP_AUTH_URL = ["ldap://10.10.10.13:389"]

# This variable is used by the Interlock back-end to respond the correct domain info to the Front-end
LDAP_DOMAIN = "brconsulting"

# Initiate TLS on connection.
LDAP_AUTH_USE_TLS = False

# Specify which TLS version to use (Python 3.10 requires TLSv1 or higher)
import ssl
LDAP_AUTH_TLS_VERSION = ssl.PROTOCOL_TLSv1_2

# The LDAP search base for looking up users.
LDAP_AUTH_SEARCH_BASE = "dc=brconsulting"

# The LDAP class that represents a user.
LDAP_AUTH_OBJECT_CLASS = "person"

# Set this to False if you wish to include Computer Accounts in User Listings
EXCLUDE_COMPUTER_ACCOUNTS = True

# User model fields mapped to the LDAP
# attributes that represent them.
LDAP_AUTH_USER_FIELDS = {
    "username": "sAMAccountName",
    "first_name": "givenName",
    "last_name": "sn",
    "email": "mail"
}

if str(LDAP_AUTH_USER_FIELDS["username"]).lower() == 'samaccountname':
    LDAP_AUTH_USERNAME_IDENTIFIER = "sAMAccountName"
else:
    LDAP_AUTH_USERNAME_IDENTIFIER = LDAP_AUTH_USER_FIELDS["username"]

# A tuple of django model fields used to uniquely identify a user.
LDAP_AUTH_USER_LOOKUP_FIELDS = (
    "username",
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
LDAP_AUTH_ACTIVE_DIRECTORY_DOMAIN = "BRCONS"

# The LDAP username and password of a user for querying the LDAP database for user
# details. If None, then the authenticated user will be used for querying, and
# the `ldap_sync_users` command will perform an anonymous query.
LDAP_AUTH_CONNECTION_USER_DN = "CN=s-ldapsync,OU=Service Accounts,DC=brconsulting"

LDAP_AUTH_CONNECTION_USERNAME = LDAP_AUTH_CONNECTION_USER_DN.split(',')[0].split('CN=')[1]
LDAP_AUTH_CONNECTION_PASSWORD = "!kDZladKxt-Ed2QI7P2eN5"

# Set connection/receive timeouts (in seconds) on the underlying `ldap3` library.
LDAP_AUTH_CONNECT_TIMEOUT = 5
LDAP_AUTH_RECEIVE_TIMEOUT = 5

ADMIN_GROUP_TO_SEARCH = "CN=admins,OU=Administrators,DC=brconsulting"

def sync_user_relations(user, ldap_attributes, *, connection=None, dn=None):
    GROUP_TO_SEARCH = ADMIN_GROUP_TO_SEARCH
    if 'Administrator' in ldap_attributes[LDAP_AUTH_USER_FIELDS["username"]]:
        user.is_staff = True
        user.is_superuser = True
        user.dn = str(ldap_attributes['distinguishedName']).lstrip("['").rstrip("']")
        user.save()
        pass
    elif 'memberOf' in ldap_attributes and GROUP_TO_SEARCH in ldap_attributes['memberOf']:
        # Do staff shit here
        user.is_staff = True
        user.is_superuser = True
        if user.email is not None:
            user.email = str(ldap_attributes['mail']).lstrip("['").rstrip("']") or ""
        user.dn = str(ldap_attributes['distinguishedName']).lstrip("['").rstrip("']")
        user.save()
    else:
        user.is_staff = True
        user.is_superuser = False
        if user.email is not None:
            user.email = str(ldap_attributes['mail']).lstrip("['").rstrip("']") or ""
        user.dn = str(ldap_attributes['distinguishedName']).lstrip("['").rstrip("']")
        user.save()
    pass



LDAP_AUTH_SYNC_USER_RELATIONS = sync_user_relations

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
LDAP_LOG_MAX = 100

SETTINGS_WITH_ALLOWABLE_OVERRIDE = {
    "LDAP_AUTH_URL":{ 
        "type": "ldap_uri", 
        "value": "" 
    },
    "LDAP_DOMAIN":{
        "value": "" 
    },
    "LDAP_LOG_MAX":{
        "type": "integer",
    },
    "LDAP_LOG_READ":{
        "type": "boolean",
    },
    "LDAP_LOG_CREATE":{
        "type": "boolean",
    },
    "LDAP_LOG_UPDATE":{
        "type": "boolean",
    },
    "LDAP_LOG_DELETE":{
        "type": "boolean",
    },
    "LDAP_LOG_OPEN_CONNECTION":{
        "type": "boolean",
    },
    "LDAP_LOG_CLOSE_CONNECTION":{
        "type": "boolean",
    },
    "LDAP_AUTH_USE_TLS":{ 
        "type": "boolean", 
        "value": "" 
    },
    "LDAP_AUTH_TLS_VERSION":{
        "value": "" ,
        "type": "select"
    },
    "LDAP_AUTH_SEARCH_BASE":{
        "value": "" 
    },
    "LDAP_AUTH_OBJECT_CLASS":{ 
        "value": "" 
    },
    "EXCLUDE_COMPUTER_ACCOUNTS":{ 
        "type": "boolean", 
        "value": "" 
    },
    "LDAP_AUTH_USER_FIELDS":{ 
        "type": "object", 
        "value": "" 
    },
    "LDAP_DIRTREE_OU_FILTER":{ 
        "type": "object"
    },
    "LDAP_DIRTREE_CN_FILTER":{ 
        "type": "object"
    },
    "LDAP_AUTH_ACTIVE_DIRECTORY_DOMAIN":{ 
        "value": ""
    },
    "LDAP_AUTH_CONNECTION_USER_DN":{ 
        "value": ""
    },
    "LDAP_AUTH_CONNECTION_USERNAME":{ 
        "value": ""
    },
    "LDAP_AUTH_CONNECTION_PASSWORD":{ 
        "type": "password",
        "value": ""
    },
    "LDAP_AUTH_CONNECT_TIMEOUT":{ 
        "type": "integer", 
        "value": ""
    },
    "LDAP_AUTH_RECEIVE_TIMEOUT":{ 
        "type": "integer", 
        "value": ""
    },
    "LDAP_AUTH_RECEIVE_TIMEOUT":{ 
        "type": "integer", 
        "value": ""
    },
    "ADMIN_GROUP_TO_SEARCH":{
        "value": ""
    }
}
