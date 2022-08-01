
from interlock_backend.ldap.adsi import (
    addSearchFilter, 
    LDAP_BUILTIN_OBJECTS,
    getDefaultFilterFor
)
from interlock_backend.ldap.settings_func import SettingsList, getSetting
from interlock_backend.ldap.connector import openLDAPConnection
import ldap3

def buildFilterFromDict(dictArray, operator="|"):
    search_filter = ""
    for key, objectType in dictArray.items():
        search_filter = addSearchFilter(search_filter, objectType + "=" + key, operator)
    return search_filter

def getBaseLevelDirectoryTree(queryFilter=None):
    """ Gets all objects in LDAP Server base subtree level.

    No arguments required

    Returns a list/array.
    """
    ldap_settings_list = SettingsList(**{"search":{
        'LDAP_AUTH_SEARCH_BASE'
    }})

    connection = openLDAPConnection()

    if queryFilter is None:
        queryFilter = getDefaultFilterFor('OU')

    connection.search(
        search_base=ldap_settings_list.LDAP_AUTH_SEARCH_BASE,
        search_filter=queryFilter,
        search_scope='LEVEL',
        attributes=ldap3.ALL_ATTRIBUTES)
    searchResult = connection.entries
    connection.unbind()
    return searchResult

def getFullDirectoryTree(connection=None, getCNs=True, ouFilter=None, cnFilter=None, getOUs=True, disableBuiltIn=False):
    """ Gets a list of the full directory tree in an LDAP Server.

    ouFilter is disabled on nested objects by default for optimization reasons.
    No arguments required

    Returns a list.
    """
    if connection is None:
        raise Exception("A connection is required")
    if ouFilter is None:
        ouFilter=getDefaultFilterFor('OU')
    if cnFilter is None:
        cnFilter=getDefaultFilterFor('CN')

    base_list = getBaseLevelDirectoryTree(ouFilter)
    result = []
    currentID = 0

    # For each entity in the base level list
    for entity in base_list:
        # Set DN from Abstract Entry object (LDAP3)
        distinguishedName=entity.entry_dn
        currentEntity = {}
        # Set ID
        currentEntity['name'] = str(distinguishedName).split(',')[0].split('=')[1]
        currentEntity['id'] = currentID
        currentEntity['dn'] = distinguishedName
        currentEntity['type'] = str(entity.objectCategory).split(',')[0].split('=')[1]
        if currentEntity['name'] in LDAP_BUILTIN_OBJECTS or 'builtinDomain' in entity.objectClass:
            currentEntity['builtin'] = True
        # Get children
        children = get_children(
            dn=distinguishedName,
            connection=connection,
            recursive=True,
            getCNs=getCNs,
            id=currentID,
            ouFilter=ouFilter,
            cnFilter=cnFilter,
            getOUs=getOUs
        )
        childrenResult = children['results']
        currentID = children['currentID']
        # Add children to parent
        currentEntity['children'] = childrenResult
        if 'builtin' in currentEntity:
            if disableBuiltIn != True and currentEntity['builtin'] == True:
                result.append(currentEntity)
                currentID += 1
        else:
            result.append(currentEntity)
            currentID += 1
    connection.unbind()
    # logger.debug(json.dumps(result, sort_keys=False, indent=2))
    return({
        "results": result,
        "connection": connection
    })

def get_children(dn, connection, recursive=False, getCNs=True, getOUs=True, id=0, ouFilter=None, cnFilter=None):
    """ Gets children for dn object in LDAP Server.

    REQUIRED
    dn: Object DN to query
    connection: LDAP Connection Object, see function openLDAPConnection()

    DEFAULTS
    Recursive: False (Set this to True to get the entire subtree below)
    getCNs: True (Set to False to get only children OUs)
    id: 0 (Use this if you need to return the items with an id to your endpoint)
    ouFilter: Required, default is None - See functions getDefaultFilterFor / buildFilterFromDict
    cnFilter: Required, default is None - See functions getDefaultFilterFor / buildFilterFromDict
    """
    if ouFilter is None:
        raise Exception("ouFilter cannot be None")
    if cnFilter is None:
        raise Exception("cnFilter cannot be None")

    ldap_settings_list = SettingsList(**{"search":{
        'LDAP_AUTH_USERNAME_IDENTIFIER'
    }})

    # Initialize Variables
    results = list()
    # Get CN Children Objects
    if getCNs == True:
        cn_results = get_children_cn(
            dn=dn,
            connection=connection,
            id=id,
            queryFilter=cnFilter,
            authUsernameIdentifier=ldap_settings_list.LDAP_AUTH_USERNAME_IDENTIFIER
        )
        id = cn_results['currentID']
        results = cn_results['results']
    # Get OU Children Objects
    if getOUs == True:
        ou_results = get_children_ou(
            dn=dn,
            connection=connection,
            recursive=recursive,
            getCNs=getCNs,
            id=id,
            cnFilter=cnFilter,
            authUsernameIdentifier=ldap_settings_list.LDAP_AUTH_USERNAME_IDENTIFIER
        )
        id = ou_results['currentID']
        ou_results = ou_results['results']
        results.extend(ou_results)
    return({
        "results": results,
        "currentID": id
    })

def get_children_cn(dn, connection, id=0, queryFilter=None, authUsernameIdentifier=None):
    """
    Gets all CN Object children for the provided Distinguished Name
    """
    ########################################################################
    if authUsernameIdentifier is None:
        raise Exception("authUsernameIdentifier cannot be None")
    if queryFilter is None:
        raise Exception("queryFilter cannot be None")
    # Initialize Variables
    results = list()
    # Send Query to LDAP Server(s)
    cnSearch = connection.extend.standard.paged_search(
        search_base=dn,
        search_filter=queryFilter,
        search_scope='LEVEL',
        attributes=[
            'objectClass', 
            'objectCategory',
            authUsernameIdentifier,
            'cn'
        ]
    )
    # Loops for every CN Object in the Query Result and adds it to array
    for cnObject in cnSearch:
        currentEntity = {}
        if 'dn' in cnObject:
            if cnObject['dn'] != dn and 'dn' in cnObject:
                id += 1
                objectClasses = cnObject['attributes']['objectClass']
                objectCategory = str(cnObject['attributes']['objectCategory']).split(',')[0].split('=')[-1].lower()
                if objectCategory == 'user' or objectCategory == 'person':
                    currentEntity['username'] = str(cnObject['attributes'][authUsernameIdentifier][0])
                elif objectCategory == 'group':
                    currentEntity['cn'] = str(cnObject['attributes']['cn'][0])
                if 'builtinDomain' in objectClasses:
                    currentEntity['builtin'] = True
                objectCategory = cnObject['attributes']['objectCategory']
                currentEntity['dn'] = cnObject['dn']
                currentEntity['name'] = str(cnObject['dn']).split(',')[0].split('=')[1]
                currentEntity['id'] = id
                currentEntity['type'] = str(objectCategory).split(',')[0].split('=')[1]
                results.append(currentEntity)
    return({
        "results": results,
        "currentID": id,
        "connection": connection
    })

def get_children_ou(dn, connection, recursive=False, getCNs=False, id=0, ouFilter=None, cnFilter=None, authUsernameIdentifier=None):
    """
    Gets all OU and (optionally) CN Object children for the provided Distinguished Name
    Passing an OU Filter is NOT recommended for optimization reasons.
    """
    # Initialize Variables
    results = list()
    if ouFilter is None:
        ouFilter = "(objectClass=organizationalUnit)"
    if getCNs == True and authUsernameIdentifier is None:
        raise Exception("authUsernameIdentifier cannot be None")
    if getCNs == True and cnFilter is None:
        raise Exception("cnFilter cannot be None")

    # Send Query to LDAP Server(s)
    childrenOU = connection.extend.standard.paged_search(
        search_base=dn,
        search_filter=ouFilter,
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
                cn_results = get_children_cn(
                    dn=ouChild['dn'],
                    connection=connection,
                    id=id,
                    queryFilter=cnFilter,
                    authUsernameIdentifier=authUsernameIdentifier
                )
                if cn_results and cn_results['results'] != []:
                    id = cn_results['currentID']
                    cn_results = cn_results['results']
                    currentEntity['children'] = cn_results
            # If function is called as recursive it will call itself again
            if recursive == True:
                ou_results = get_children_ou(
                    dn=ouChild['dn'],
                    connection=connection,
                    recursive=recursive,
                    getCNs=getCNs,
                    id=id,
                    cnFilter=cnFilter,
                    authUsernameIdentifier=authUsernameIdentifier
                )
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
        "currentID": id,
        "connection": connection
    })
