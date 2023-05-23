# This file is generated automatically by Interlock when saving settings
# Manual changes to it might be lost
################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: constants_cache.py
# Contains the latest setting constants for Interlock

#---------------------------------- IMPORTS -----------------------------------#
from interlock_backend.ldap.constants import *
import ssl
################################################################################

LDAP_AUTH_URL=['ldap://10.1.200.101:389']
LDAP_DOMAIN="estudioferro.com.ar"
LDAP_AUTH_USE_TLS=True
LDAP_AUTH_SEARCH_BASE="DC=estudioferro,DC=com,DC=ar"
LDAP_AUTH_ACTIVE_DIRECTORY_DOMAIN="ESTUDIOFERRO"
LDAP_AUTH_CONNECTION_USER_DN="CN=Administrator,CN=Users,DC=estudioferro,DC=com,DC=ar"
LDAP_AUTH_CONNECTION_USERNAME="administrator"
LDAP_AUTH_CONNECTION_PASSWORD="gAAAAABkbCAoASTQ0fXXkVKsG0J4wIEOw4lYK0RWO9r4uY38Em_z9uK9NOzUPkCzO-EvngNyoi_4d6_ycpZ2MXKLmh-wqZ_NqNuID9NjBFOUh8M-ecJn5eY="
ADMIN_GROUP_TO_SEARCH="CN=Administrators,CN=Builtin,DC=estudioferro,DC=com,DC=ar"