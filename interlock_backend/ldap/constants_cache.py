from interlock_backend.ldap.constants import *
import ssl

LDAP_AUTH_URL=['ldaps://10.10.10.1:636']
LDAP_DOMAIN="brconsulting.info"
LDAP_AUTH_USE_TLS=True
LDAP_AUTH_SEARCH_BASE="DC=brconsulting,DC=info"
LDAP_AUTH_ACTIVE_DIRECTORY_DOMAIN="BRCONS"
LDAP_AUTH_CONNECTION_USER_DN="CN=Administrator,CN=Users,DC=brconsulting,DC=info"
LDAP_AUTH_CONNECTION_USERNAME="administrator"
LDAP_AUTH_CONNECTION_PASSWORD="ISJuAAqfgjshjkAE4fR8"
ADMIN_GROUP_TO_SEARCH="CN=Super Administrators,OU=BR Consulting,DC=brconsulting,DC=info"