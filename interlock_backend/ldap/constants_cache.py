from interlock_backend.ldap.constants import *
import ssl

LDAP_AUTH_URL=['ldaps://10.10.10.1:636']
LDAP_DOMAIN="brconsulting.info"
LDAP_LOG_MAX=100
LDAP_LOG_READ=False
LDAP_LOG_CREATE=True
LDAP_LOG_UPDATE=True
LDAP_LOG_DELETE=True
LDAP_LOG_OPEN_CONNECTION=False
LDAP_LOG_CLOSE_CONNECTION=False
LDAP_LOG_LOGIN=False
LDAP_LOG_LOGOUT=False
LDAP_AUTH_USE_TLS=True
LDAP_AUTH_TLS_VERSION=ssl.PROTOCOL_TLSv1_2
LDAP_AUTH_SEARCH_BASE="DC=brconsulting,DC=info"
LDAP_AUTH_OBJECT_CLASS="person"
EXCLUDE_COMPUTER_ACCOUNTS=True
LDAP_AUTH_USER_FIELDS={
    "username": "sAMAccountName",
    "first_name": "givenName",
    "last_name": "sn",
    "email": "mail",
    "dn": "distinguishedName"
}
LDAP_DIRTREE_OU_FILTER={
    "organizationalUnit": "objectCategory",
    "top": "objectCategory",
    "container": "objectCategory",
    "builtinDomain": "objectClass"
}
LDAP_DIRTREE_CN_FILTER={
    "user": "objectClass",
    "person": "objectClass",
    "group": "objectClass",
    "organizationalPerson": "objectClass",
    "computer": "objectClass"
}
LDAP_AUTH_ACTIVE_DIRECTORY_DOMAIN="BRCONS"
LDAP_AUTH_CONNECTION_USER_DN="CN=Administrator,CN=Users,DC=brconsulting,DC=info"
LDAP_AUTH_CONNECTION_USERNAME="administrator"
LDAP_AUTH_CONNECTION_PASSWORD="ISJuAAqfgjshjkAE4fR8"
LDAP_AUTH_CONNECT_TIMEOUT=5
LDAP_AUTH_RECEIVE_TIMEOUT=5
ADMIN_GROUP_TO_SEARCH="CN=admins,OU=Administrators,DC=brconsulting"