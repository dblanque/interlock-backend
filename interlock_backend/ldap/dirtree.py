
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

    search_filter=""
    search_filter=addSearchFilter(search_filter, 'objectCategory=organizationalUnit')
    search_filter=addSearchFilter(search_filter, 'objectCategory=top', "|")
    search_filter=addSearchFilter(search_filter, 'objectCategory=container', "|")
    search_filter=addSearchFilter(search_filter, 'objectCategory=builtinDomain', "|")
    connection.search(
        search_base=ldap_settings_list.LDAP_AUTH_SEARCH_BASE,
        search_filter=search_filter,
        search_scope='LEVEL',
        attributes=ldap3.ALL_ATTRIBUTES)
    searchResult = connection.entries
    connection.unbind()
    return searchResult

def getFullDirectoryTree(getCNs=True, queryFilter=None):
    """ Gets a list of the full directory tree in an LDAP Server.

    No arguments required

    Returns a list.
    """
    base_list = getBaseLevelDirectoryTree()
    result = []
    connection = openLDAPConnection()
    currentID = 0

    # TODO Join the base directory tree fetch onto the same function as the others
    # Why separate it?

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
        if currentEntity['name'] in LDAP_BUILTIN_OBJECTS or 'builtinDomain' in entity.objectClass:
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
    # logger.debug(json.dumps(result, sort_keys=False, indent=2))
    return result

def get_children(dn, connection, recursive=False, getCNs=True, id=0):
    """ Gets children for dn object in LDAP Server.

    REQUIRED
    dn: Object DN to query
    connection: LDAP Connection Object, see function openLDAPConnection()

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

def get_children_cn(dn, connection, id=0):
    ######################## Get Latest Settings ###########################
    authUsernameIdentifier = getSetting('LDAP_AUTH_USERNAME_IDENTIFIER')
    ########################################################################
    # Add filters
    search_filter = getDefaultFilterFor("cn")
    # Initialize Variables
    results = list()
    # Send Query to LDAP Server(s)
    cnSearch = connection.extend.standard.paged_search(
        search_base=dn,
        search_filter=search_filter,
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
        "currentID": id
    })

def get_children_ou(dn, connection, recursive=False, getCNs=False, id=0):
    # Initialize Variables
    results = list()
    search_filter = getDefaultFilterFor("cn")
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
