################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: core.ldap.types.group
from enum import Enum


class LDAPGroupTypes(Enum):
	# Types
	TYPE_DISTRIBUTION = 0
	TYPE_SYSTEM = 1
	TYPE_SECURITY = 2147483648
	# Scopes
	SCOPE_GLOBAL = 2
	SCOPE_DOMAIN_LOCAL = 4
	SCOPE_UNIVERSAL = 8


LDAP_GROUP_TYPES = {t.name: t.value for t in LDAPGroupTypes}

# Group Type Value Mapping
MAPPED_GROUP_TYPE_DISTRIBUTION = 0
MAPPED_GROUP_TYPE_SECURITY = 1
LDAP_GROUP_TYPE_MAPPING = {
	# Distribution Group
	MAPPED_GROUP_TYPE_DISTRIBUTION: LDAPGroupTypes.TYPE_DISTRIBUTION.value,
	# Security Group
	MAPPED_GROUP_TYPE_SECURITY: -LDAPGroupTypes.TYPE_SECURITY.value,
}

# Group Scope Value Mapping
MAPPED_GROUP_SCOPE_GLOBAL = 0
MAPPED_GROUP_SCOPE_DOMAIN_LOCAL = 1
MAPPED_GROUP_SCOPE_UNIVERSAL = 2
LDAP_GROUP_SCOPE_MAPPING = {
	# Global Scope
	MAPPED_GROUP_SCOPE_GLOBAL: LDAPGroupTypes.SCOPE_GLOBAL.value,
	# Domain Local Scope
	MAPPED_GROUP_SCOPE_DOMAIN_LOCAL: LDAPGroupTypes.SCOPE_DOMAIN_LOCAL.value,
	# Universal Scope
	MAPPED_GROUP_SCOPE_UNIVERSAL: LDAPGroupTypes.SCOPE_UNIVERSAL.value,
}
