################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: core.constants.attrs.ldap
# Contains system LDAP Attribute related constants.
################################################################################

# Global
ADDS_VERSION_OIDS = {
	"1.2.840.113556.1.4.800": "Windows 2000",
	"1.2.840.113556.1.4.1670": "Windows 2003",
	"1.2.840.113556.1.4.1791": "Windows 2003 R2",
	"1.2.840.113556.1.4.1935": "Windows 2008",
	"1.2.840.113556.1.4.2080": "Windows 2008 R2",
	"1.2.840.113556.1.4.2237": "Windows 2012",
	"1.2.840.113556.1.4.2255": "Windows 2012 R2",
	"1.2.840.113556.1.4.2309": "Windows 2016",
	"1.2.840.113556.1.4.2330": "Windows 2019",
	"1.2.840.113556.1.4.2383": "Windows 2022",
	"1.2.840.113556.1.4.2239": ("DNSSEC", True),
}
LDAP_DATE_FORMAT = "%Y%m%d%H%M%S.%fZ"
LDAP_ESCAPE_REQUIRED_CHARS = (
	"+",
	";",
	",",
	"\\",
	'"',
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
LDAP_ATTR_GUID = "objectGUID"
LDAP_ATTR_ACCOUNT_TYPE = "sAMAccountType"
LDAP_ATTR_USER_GROUPS = "memberOf"
LDAP_ATTR_INITIALS = "initials"
LDAP_ATTR_COMMON_NAME = "cn"
LDAP_ATTR_GROUP_MEMBERS = "member"
LDAP_ATTR_GROUP_TYPE = "groupType"
LDAP_ATTR_LOGON_TIMESTAMP = "lastLogonTimestamp"
LDAP_ATTR_EXPIRES_AT = "accountExpires"
