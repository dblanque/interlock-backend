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
