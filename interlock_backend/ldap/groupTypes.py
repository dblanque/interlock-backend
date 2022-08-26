################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: interlock_backend.ldap.groupTypes

LDAP_GROUP_TYPES = {
    "GROUP_DISTRIBUTION": 0,
    "GROUP_SYSTEM": 1,
    "GROUP_GLOBAL": 2,
    "GROUP_DOMAIN_LOCAL": 4,
    "GROUP_UNIVERSAL": 8,
    "GROUP_SECURITY": 2147483648
}