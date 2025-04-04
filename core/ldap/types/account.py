################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: interlock_backend.ldap.accountTypes

# ---------------------------------- IMPORTS -----------------------------------#
LDAP_ACCOUNT_TYPES = {
	"SAM_DOMAIN_OBJECT": int(0x0),
	"SAM_GROUP_OBJECT": int(0x10000000),
	"SAM_NON_SECURITY_GROUP_OBJECT": int(0x10000001),
	"SAM_ALIAS_OBJECT": int(0x20000000),
	"SAM_NON_SECURITY_ALIAS_OBJECT": int(0x20000001),
	"SAM_USER_OBJECT": int(0x30000000),
	"SAM_NORMAL_USER_ACCOUNT": int(0x30000000),
	"SAM_MACHINE_ACCOUNT": int(0x30000001),
	"SAM_TRUST_ACCOUNT": int(0x30000002),
	"SAM_APP_BASIC_GROUP": int(0x40000000),
	"SAM_APP_QUERY_GROUP": int(0x40000001),
	"SAM_ACCOUNT_TYPE_MAX": int(0x7FFFFFFF),
}
