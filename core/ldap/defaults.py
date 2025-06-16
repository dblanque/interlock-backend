################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: core.ldap.defaults
from core.constants.attrs import *

### LDAP SETTINGS
# ! You also have to add the settings to the following files:
# core.models.ldap_settings
# core.models.ldap_settings_db
# core.ldap.defaults	<------------ You're Here

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

# Set this to False if you wish to include Computer Accounts in User Listings
EXCLUDE_COMPUTER_ACCOUNTS = True

# Set this if you want to only use the settings in this constants,
# Overrides will stop having an effect on system calls
DISABLE_SETTING_OVERRIDES = False

# Change in OpenLDAP
LDAP_OU_FIELD = LDAP_ATTR_USERNAME_SAMBA_ADDS
LDAP_GROUP_FIELD = LDAP_ATTR_USERNAME_SAMBA_ADDS

# Model fields mapped to the LDAP attributes that represent them.
LDAP_FIELD_MAP = {
	LOCAL_ATTR_DN: LDAP_ATTR_DN,
	LOCAL_ATTR_USERNAME: LDAP_ATTR_USERNAME_SAMBA_ADDS,
	LOCAL_ATTR_EMAIL: LDAP_ATTR_EMAIL,
	LOCAL_ATTR_PASSWORD: LDAP_ATTR_PASSWORD,
	LOCAL_ATTR_FIRST_NAME: LDAP_ATTR_FIRST_NAME,
	LOCAL_ATTR_LAST_NAME: LDAP_ATTR_LAST_NAME,
	LOCAL_ATTR_FULL_NAME: LDAP_ATTR_FULL_NAME,
	LOCAL_ATTR_INITIALS: LDAP_ATTR_INITIALS,
	LOCAL_ATTR_PHONE: LDAP_ATTR_PHONE,
	LOCAL_ATTR_ADDRESS: LDAP_ATTR_ADDRESS,
	LOCAL_ATTR_POSTAL_CODE: LDAP_ATTR_POSTAL_CODE,
	LOCAL_ATTR_CITY: LDAP_ATTR_CITY,
	LOCAL_ATTR_STATE: LDAP_ATTR_STATE,
	LOCAL_ATTR_COUNTRY: LDAP_ATTR_COUNTRY,
	LOCAL_ATTR_COUNTRY_DCC: LDAP_ATTR_COUNTRY_DCC,
	LOCAL_ATTR_COUNTRY_ISO: LDAP_ATTR_COUNTRY_ISO,
	LOCAL_ATTR_WEBSITE: LDAP_ATTR_WEBSITE,
	LOCAL_ATTR_UPN: LDAP_ATTR_UPN,
	LOCAL_ATTR_UAC: LDAP_ATTR_UAC,
	LOCAL_ATTR_CREATED: LDAP_ATTR_CREATED,
	LOCAL_ATTR_MODIFIED: LDAP_ATTR_MODIFIED,
	LOCAL_ATTR_LAST_LOGIN_WIN32: LDAP_ATTR_LAST_LOGIN,
	LOCAL_ATTR_BAD_PWD_COUNT: LDAP_ATTR_BAD_PWD_COUNT,
	LOCAL_ATTR_PWD_SET_AT: LDAP_ATTR_PWD_SET_AT,
	LOCAL_ATTR_PRIMARY_GROUP_ID: LDAP_ATTR_PRIMARY_GROUP_ID,
	LOCAL_ATTR_OBJECT_CLASS: LDAP_ATTR_OBJECT_CLASS,
	LOCAL_ATTR_OBJECT_CATEGORY: LDAP_ATTR_OBJECT_CATEGORY,
	LOCAL_ATTR_RELATIVE_ID: LDAP_ATTR_RELATIVE_ID,
	LOCAL_ATTR_SECURITY_ID: LDAP_ATTR_SECURITY_ID,
	LOCAL_ATTR_ACCOUNT_TYPE: LDAP_ATTR_ACCOUNT_TYPE,
	LOCAL_ATTR_USER_GROUPS: LDAP_ATTR_USER_GROUPS,
	LOCAL_ATTR_GROUP_MEMBERS: LDAP_ATTR_GROUP_MEMBERS,
	LOCAL_ATTR_LOGON_TIMESTAMP: LDAP_ATTR_LOGON_TIMESTAMP,
	LOCAL_ATTR_EXPIRES_AT: LDAP_ATTR_EXPIRES_AT,
	LOCAL_ATTR_NAME: LDAP_ATTR_COMMON_NAME,
	LOCAL_ATTR_GROUP_TYPE: LDAP_ATTR_GROUP_TYPE,
}
LDAP_FIELD_MAP[LOCAL_ATTR_COMMON_NAME] = LDAP_FIELD_MAP[LOCAL_ATTR_NAME]

# Normalize to the standard LDAP string if it's sAMAccountName just in case
if (
	str(LDAP_FIELD_MAP[LOCAL_ATTR_USERNAME]).lower()
	== LDAP_ATTR_USERNAME_SAMBA_ADDS.lower()
):
	LDAP_AUTH_USERNAME_IDENTIFIER = LDAP_ATTR_USERNAME_SAMBA_ADDS
else:
	LDAP_AUTH_USERNAME_IDENTIFIER = LDAP_FIELD_MAP[LOCAL_ATTR_USERNAME]

# A tuple of django model fields used to uniquely identify a user.
LDAP_AUTH_USER_LOOKUP_FIELDS = (LOCAL_ATTR_USERNAME, LOCAL_ATTR_EMAIL)

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
LDAP_AUTH_FORMAT_SEARCH_FILTERS = (
	"django_python3_ldap.utils.format_search_filters"
)

# Path to a callable that takes a dict of {model_field_name: value}, and returns
# a string of the username to bind to the LDAP server.
# Use this to support different types of LDAP server.
LDAP_AUTH_FORMAT_USERNAME = (
	"django_python3_ldap.utils.format_username_active_directory"
)

# Sets the login domain for Active Directory users.
LDAP_AUTH_ACTIVE_DIRECTORY_DOMAIN = "EXAMPLE"

# The LDAP username and password of a user for querying the LDAP database for user
# details. If None, then the authenticated user will be used for querying, and
# the `ldap_sync_users` command will perform an anonymous query.
# This is used when the local Interlock Admin is logged in.
LDAP_AUTH_CONNECTION_USER_DN = "CN=Administrator,CN=Users,DC=example,DC=com"

LDAP_AUTH_CONNECTION_USERNAME = LDAP_AUTH_CONNECTION_USER_DN.split(",")[
	0
].split("CN=")[1]
LDAP_AUTH_CONNECTION_PASSWORD = None

# Set connection/receive timeouts (in seconds) on the underlying `ldap3` library.
LDAP_AUTH_CONNECT_TIMEOUT = 10
LDAP_AUTH_RECEIVE_TIMEOUT = 10

ADMIN_GROUP_TO_SEARCH = "CN=Administrators,CN=Builtin,DC=example,DC=com"

# See https://en.wikipedia.org/wiki/LDAP_Data_Interchange_Format
LDAP_LDIF_IDENTIFIERS = list({"dn", "dc", "ou", "cn"})

LDAP_OPERATIONS = list(
	{
		"BIND",
		"UNBIND",
		"ADD",
		"DELETE",
		"MODIFY",
		"MODIFY-DN",
		"SEARCH",
		"COMPARE",
		"ABANDON",
		"EXTENDED",
	}
)
