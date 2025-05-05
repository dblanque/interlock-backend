# core.ldap.constants

# Global
LDAP_DATE_FORMAT = "%Y%m%d%H%M%S.%fZ"

LDAP_ESCAPE_REQUIRED_CHARS = (
	"+",
	";",
	",",
	"\\",
	"\"",
	"<",
	">",
	"#",
)

# LDAP Attributes
LDAP_ATTR_PASSWORD = "unicodePwd"
LDAP_ATTR_FIRST_NAME = "givenName"
LDAP_ATTR_LAST_NAME = "sn"
LDAP_ATTR_FULL_NAME = "displayName"
LDAP_ATTR_USERNAME_SAMBA_ADDS = "sAMAccountName"
LDAP_ATTR_EMAIL = "mail"
LDAP_ATTR_PHONE = "telephoneNumber"
LDAP_ATTR_ADDRESS = "streetAddress"
LDAP_ATTR_POSTAL_CODE = "postalCode"
LDAP_ATTR_CITY = "l"  # Local / City
LDAP_ATTR_STATE = "st"  # State/Province
LDAP_ATTR_COUNTRY = "co"
LDAP_ATTR_COUNTRY_DCC = "countryCode"
LDAP_ATTR_COUNTRY_ISO = "c"
LDAP_ATTR_WEBSITE = "wWWHomePage"
LDAP_ATTR_DN = "distinguishedName"
LDAP_ATTR_UPN = "userPrincipalName"
LDAP_ATTR_UAC = "userAccountControl"  # Permission ACLs
LDAP_ATTR_CREATED = "whenCreated"
LDAP_ATTR_MODIFIED = "whenChanged"
LDAP_ATTR_LAST_LOGIN = "lastLogon"
LDAP_ATTR_BAD_PWD_COUNT = "badPwdCount"
LDAP_ATTR_PWD_SET_AT = "pwdLastSet"
LDAP_ATTR_PRIMARY_GROUP_ID = "primaryGroupID"
LDAP_ATTR_OBJECT_CLASS = "objectClass"
LDAP_ATTR_OBJECT_CATEGORY = "objectCategory"
LDAP_ATTR_RELATIVE_ID = "objectRid"
LDAP_ATTR_SECURITY_ID = "objectSid"
LDAP_ATTR_ACCOUNT_TYPE = "sAMAccountType"
LDAP_ATTR_USER_GROUPS = "memberOf"
LDAP_ATTR_INITIALS = "initials"
LDAP_ATTR_COMMON_NAME = "cn"
LDAP_ATTR_GROUP_MEMBERS = "member"
LDAP_ATTR_GROUP_TYPE = "groupType"
# Local but related to LDAP
LOCAL_LDAP_ATTR_GROUP_SCOPE = "groupScope"

# LOCAL Attributes
LOCAL_ATTR_USERNAME = "username"
LOCAL_ATTR_PASSWORD = "password"
LOCAL_ATTR_FIRST_NAME = "first_name"
LOCAL_ATTR_LAST_NAME = "last_name"
LOCAL_ATTR_FULL_NAME = "full_name"
LOCAL_ATTR_INITIALS = "initials"
LOCAL_ATTR_PHONE = "phone"
LOCAL_ATTR_EMAIL = "email"
LOCAL_ATTRS_MAP = {
	LOCAL_ATTR_PASSWORD: LDAP_ATTR_PASSWORD,
	LOCAL_ATTR_FIRST_NAME: LDAP_ATTR_FIRST_NAME,
	LOCAL_ATTR_LAST_NAME: LDAP_ATTR_LAST_NAME,
	LOCAL_ATTR_FULL_NAME: LDAP_ATTR_FULL_NAME,
	LOCAL_ATTR_INITIALS: LDAP_ATTR_INITIALS,
	LOCAL_ATTR_USERNAME: LDAP_ATTR_USERNAME_SAMBA_ADDS,
	LOCAL_ATTR_EMAIL: LDAP_ATTR_EMAIL,
	LOCAL_ATTR_PHONE: LDAP_ATTR_PHONE,
	"street_address": LDAP_ATTR_ADDRESS,
	"postal_code": LDAP_ATTR_POSTAL_CODE,
	"city": LDAP_ATTR_CITY,
	"state_province": LDAP_ATTR_STATE,
	"country_name": LDAP_ATTR_COUNTRY,
	"country_code_dcc": LDAP_ATTR_COUNTRY_DCC,
	"country_code_iso": LDAP_ATTR_COUNTRY_ISO,
	"website": LDAP_ATTR_WEBSITE,
	"distinguished_name": LDAP_ATTR_DN,
	"user_principal_name": LDAP_ATTR_UPN,
	"user_account_control": LDAP_ATTR_UAC,
	"created_at": LDAP_ATTR_CREATED,
	"modified_at": LDAP_ATTR_MODIFIED,
	"last_login_win32": LDAP_ATTR_LAST_LOGIN,
	"bad_password_count": LDAP_ATTR_BAD_PWD_COUNT,
	"password_set_at": LDAP_ATTR_PWD_SET_AT,
	"primary_group_id": LDAP_ATTR_PRIMARY_GROUP_ID,
	"object_class": LDAP_ATTR_OBJECT_CLASS,
	"object_category": LDAP_ATTR_OBJECT_CATEGORY,
	"object_relative_id": LDAP_ATTR_RELATIVE_ID,
	"object_security_id": LDAP_ATTR_SECURITY_ID,
	"account_type": LDAP_ATTR_ACCOUNT_TYPE,
	"groups": LDAP_ATTR_USER_GROUPS,
	"members": LDAP_ATTR_GROUP_MEMBERS,
}