################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: core.ldap.types.group
from enum import Enum

class LDAPGroupTypes(Enum):
	GROUP_DISTRIBUTION = 0
	GROUP_SYSTEM = 1
	GROUP_GLOBAL = 2
	GROUP_DOMAIN_LOCAL = 4
	GROUP_UNIVERSAL = 8
	GROUP_SECURITY = 2147483648

LDAP_GROUP_TYPES = {
	t.name: t.value for t in LDAPGroupTypes
}
