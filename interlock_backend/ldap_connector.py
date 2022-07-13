from dis import dis
from unittest import result
from attr import attributes
from django_python3_ldap.ldap import Connection
from django.contrib.auth import get_user_model
from django_python3_ldap.utils import import_func, format_search_filter
from django_python3_ldap.conf import settings
from djchoices import C
import interlock_backend.ldap_settings as settings
import logging
import ldap3
from ldap3.core.exceptions import LDAPException
from .ldap_adsi import add_search_filter, LDAP_BUILTIN_OBJECTS
import json

logger = logging.getLogger(__name__)

def open_connection():
    format_username = import_func(settings.LDAP_AUTH_FORMAT_USERNAME)

    # Build server pool
    server_pool = ldap3.ServerPool(None, ldap3.RANDOM, active=True, exhaust=5)
    auth_url = settings.LDAP_AUTH_URL
    if not isinstance(auth_url, list):
        auth_url = [auth_url]
    for u in auth_url:
        server_pool.add(
            ldap3.Server(
                u,
                allowed_referral_hosts=[("*", True)],
                get_info=ldap3.NONE,
                connect_timeout=settings.LDAP_AUTH_CONNECT_TIMEOUT,
            )
        )
    # Connect.
    try:
        # Include SSL / TLS, if requested.
        connection_args = {
            "user": settings.LDAP_AUTH_CONNECTION_USER_DN,
            "password": settings.LDAP_AUTH_CONNECTION_PASSWORD,
            "auto_bind": True,
            "raise_exceptions": True,
            "receive_timeout": settings.LDAP_AUTH_RECEIVE_TIMEOUT,
        }
        if settings.LDAP_AUTH_USE_TLS:
            connection_args["tls"] = ldap3.Tls(
                ciphers='ALL',
                version=settings.LDAP_AUTH_TLS_VERSION,
            )
        c = ldap3.Connection(
            server_pool,
            **connection_args,
        )
    except LDAPException as ex:
        logger.warning("LDAP connect failed: {ex}".format(ex=ex))
        return None    
    # Configure.
    try:
        c.bind(read_server_info=True)
        # Perform initial authentication bind.
        # Rebind as specified settings username and password for querying.
        # c.rebind(
        #     user=format_username({settings.LDAP_AUTH_CONNECTION_USERNAME}),
        #     password=settings.LDAP_AUTH_CONNECTION_PASSWORD,
        # )
        # Return the connection.
        logger.debug("LDAP connect succeeded")
        return c
    except LDAPException as ex:
        logger.warning("LDAP bind failed: {ex}".format(ex=ex))
        return None

def get_base_level():
    """ Gets all objects in LDAP Server base subtree level.

    No arguments required

    Returns a list/array.
    """
    connection = open_connection()
    search_filter=""
    search_filter=add_search_filter(search_filter, 'objectCategory=organizationalUnit')
    search_filter=add_search_filter(search_filter, 'objectCategory=top', "|")
    search_filter=add_search_filter(search_filter, 'objectCategory=container', "|")
    connection.search(
        search_base=settings.LDAP_AUTH_SEARCH_BASE,
        search_filter=search_filter,
        search_scope='LEVEL',
        attributes=ldap3.ALL_ATTRIBUTES)
    searchResult = connection.entries
    connection.unbind()
    return searchResult

def get_full_directory_tree(getCNs=True):
    """ Gets a list of the full directory tree in an LDAP Server.

    No arguments required

    Returns a list.
    """
    base_list = get_base_level()
    result = []
    connection = open_connection()
    currentID = 0

    # For each entity in the base level list
    for entity in base_list:
        # Set DN from Abstract Entry object (LDAP3)
        distinguishedName=entity.entry_dn
        currentEntity = {}
        # Set ID
        currentEntity['dn'] = distinguishedName
        currentEntity['name'] = str(distinguishedName).split(',')[0].split('=')[1]
        currentEntity['id'] = currentID
        currentEntity['type'] = str(entity.objectCategory).split(',')[0].split('=')[1]
        if currentEntity['name'] in LDAP_BUILTIN_OBJECTS:
            currentEntity['builtin'] = True
        # Get children
        children = get_children(distinguishedName, connection, recursive=True, getCNs=getCNs, id=currentID)
        childrenResult = children['results']
        currentID = children['currentID']
        # Add children to parent
        currentEntity['children'] = childrenResult
        result.append(currentEntity)
        currentID += 1
    connection.unbind()
    logger.debug(json.dumps(result, sort_keys=False, indent=2))
    return result

def get_children_cn(dn, connection, id=0):
    # Add filters
    search_filter='(objectClass=person)'
    search_filter=add_search_filter(search_filter, 'objectClass=user', "|")
    search_filter=add_search_filter(search_filter, 'objectClass=group', "|")
    search_filter=add_search_filter(search_filter, 'objectClass=organizationalPerson', "|")
    search_filter=add_search_filter(search_filter, 'objectClass=computer', "|")
    # Initialize Variables
    results = list()
    # Send Query to LDAP Server(s)
    cnSearch = connection.extend.standard.paged_search(
        search_base=dn,
        search_filter=search_filter,
        search_scope='LEVEL',
        attributes=['objectClass', 'objectCategory','sAMAccountName'])
    # Loops for every CN Object in the Query Result and adds it to array
    for cnObject in cnSearch:
        currentEntity = {}
        if 'dn' in cnObject:
            if cnObject['dn'] != dn and 'dn' in cnObject:
                id += 1
                objectClasses = cnObject['attributes']['objectClass']
                if 'user' or 'person' in objectClasses:
                    currentEntity['username'] = str(cnObject['attributes']['sAMAccountName'][0])
                objectCategory = cnObject['attributes']['objectCategory']
                currentEntity['dn'] = cnObject['dn']
                currentEntity['name'] = str(cnObject['dn']).split(',')[0].split('=')[1]
                currentEntity['id'] = id
                currentEntity['type'] = str(objectCategory).split(',')[0].split('=')[1]
                results.append(currentEntity)
    return({
        "results": results,
        "currentID": id
    })

def get_children_ou(dn, connection, recursive=False, getCNs=False, id=0):
    # Initialize Variables
    results = list()
    # Send Query to LDAP Server(s)
    childrenOU = connection.extend.standard.paged_search(
        search_base=dn,
        search_filter='(objectCategory=organizationalUnit)',
        search_scope='LEVEL')
    # Loops for every child Organization Unit
    for ouChild in childrenOU:
        # If OU Child has a DN and it's not the same as the parent
        if 'dn' in ouChild and ouChild['dn'] != dn:
            id += 1
            currentEntity = {}
            currentEntity['dn'] = ouChild['dn']
            currentEntity['name'] = str(ouChild['dn']).split(',')[0].split('=')[1]
            currentEntity['id'] = id
            currentEntity['type'] = 'Organizational-Unit'
            # If this is true then it will fetch the children CN Objects
            if getCNs == True:
                cn_results = get_children_cn(ouChild['dn'], connection, id)
                if cn_results and cn_results['results'] != []:
                    id = cn_results['currentID']
                    cn_results = cn_results['results']
                    currentEntity['children'] = cn_results
            # If function is called as recursive it will call itself again
            if recursive == True:
                ou_results = get_children_ou(ouChild['dn'], connection, recursive, getCNs, id)
                if ou_results and ou_results['results'] != []:
                    id = ou_results['currentID']
                    ou_results = ou_results['results']
                    if 'children' not in currentEntity:
                        currentEntity['children'] = ou_results
                    else:
                        currentEntity['children'].extend(ou_results)
            results.append(currentEntity)
    return({
        "results": results,
        "currentID": id
    })

def get_children(dn, connection, recursive=False, getCNs=True, id=0):
    """ Gets children for dn object in LDAP Server.

    REQUIRED
    dn: Object DN to query
    connection: LDAP Connection Object, see function open_connection()

    DEFAULTS
    Recursive: False (Set this to True to get the entire subtree below)
    getCNs: True (Set to False to get only children OUs)
    id: 0 (Use this if you need to return the items with an id to your endpoint)
    """
    # Initialize Variables
    results = list()
    # Get CN Children Objects
    if getCNs == True:
        cn_results = get_children_cn(dn, connection, id)
        id = cn_results['currentID']
        results = cn_results['results']
    # Get OU Children Objects
    ou_results = get_children_ou(dn, connection, recursive, getCNs, id=id)
    id = ou_results['currentID']
    ou_results = ou_results['results']
    results.extend(ou_results)
    return({
        "results": results,
        "currentID": id
    })

