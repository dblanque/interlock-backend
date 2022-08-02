from django.utils.translation import gettext_lazy as _
from interlock_backend.ldap.settings_func import SettingsList
from interlock_backend.ldap.adsi import (
    buildFilterFromDict,
    LDAP_BUILTIN_OBJECTS
)
from interlock_backend.ldap.securityIdentifier import SID
class LDAPTree():
    """
    ## LDAPTree Object
    Fetches LDAP Directory Tree from the default Search Base or a specified Level

    ### Call example
    LDAPTree(**{
        "key":"val",\n
        ...
    })

    #### Arguments
     - searchBase: (OPTIONAL) | Default: LDAP_AUTH_SEARCH_BASE
     - connection: (REQUIRED) | LDAP Connection Object
     - recursive: (OPTIONAL) | Whether or not the Tree should be Recursively searched)
     - ldapFilter: (OPTIONAL) | LDAP Formatted Filter
     - ldapAttributes: (OPTIONAL) | LDAP Attributes to Fetch
     - excludedLdapAttributes: (OPTIONAL) | LDAP Attributes to Exclude
     - childrenObjectType: (OPTIONAL) | Default: List/Array - Can be dict() or list()
     - testFetch: (OPTIONAL) | Default: False - Only fetch one object to test
    """
    use_in_migrations = False

    def __init__(self, **kwargs):
        if 'connection' not in kwargs:
            raise Exception("LDAPTree object requires an LDAP Connection to Initialize")

        ldap_settings_list = SettingsList(**{"search":{
            'LDAP_AUTH_SEARCH_BASE',
            'LDAP_AUTH_USERNAME_IDENTIFIER',
            'LDAP_DIRTREE_OU_FILTER',
            'LDAP_DIRTREE_CN_FILTER',
            'LDAP_DIRTREE_ATTRIBUTES',
        }})

        # Set LDAPTree Default Values
        self.name = ldap_settings_list.LDAP_AUTH_SEARCH_BASE
        self.searchBase = ldap_settings_list.LDAP_AUTH_SEARCH_BASE
        self.connection = kwargs.pop('connection')
        self.usernameIdentifier = ldap_settings_list.LDAP_AUTH_USERNAME_IDENTIFIER
        self.subobjectId = 0
        self.excludedLdapAttributes = [
            'objectGUID',
            'objectSid'
        ]
        self.requiredLdapAttributes = [
            'dn',
            'objectCategory',
            'objectClass'
        ]
        self.containerTypes = [
            'container',
            'organizational-unit'
        ]
        self.recursive = False
        self.testFetch = False        
        self.ldapFilter = buildFilterFromDict({**ldap_settings_list.LDAP_DIRTREE_CN_FILTER, **ldap_settings_list.LDAP_DIRTREE_OU_FILTER})
        self.ldapAttributes = ldap_settings_list.LDAP_DIRTREE_ATTRIBUTES
        self.childrenObjectType = 'array'

        # Set required attributes, these are unremovable from the tree searches
        for attr in self.requiredLdapAttributes:
            if attr not in self.ldapAttributes:
                self.ldapAttributes.append(attr)

        # Set passed kwargs from Object Call
        for kw in kwargs:
            setattr(self, kw, kwargs[kw])

        self.children = self.__getLdapTree__()


    def __getLdapTree__(self):
        self.connection.search(
            search_base     = self.searchBase,
            search_filter   = self.ldapFilter,
            search_scope    = 'LEVEL',
            attributes      = self.ldapAttributes
        )
        baseLevelList = self.connection.entries
        if self.childrenObjectType == 'array':
            children = list()
        else:
            children = dict()

        if self.testFetch == True:
            baseLevelList = [ baseLevelList[0] ]

        # For each entity in the base level list
        for entity in baseLevelList:
            # Set DN from Abstract Entry object (LDAP3)
            distinguishedName=entity.entry_dn
            # Set entity attributes
            currentEntity = {}
            currentEntity['name'] = str(distinguishedName).split(',')[0].split('=')[1]
            currentEntity['id'] = self.subobjectId
            currentEntity['dn'] = distinguishedName
            currentEntity['type'] = str(entity.objectCategory).split(',')[0].split('=')[1]
            if currentEntity['name'] in LDAP_BUILTIN_OBJECTS or 'builtinDomain' in entity.objectClass:
                currentEntity['builtin'] = True

            ##################################
            # Recursive Children Search Here #
            ##################################
            if self.recursive == True:
                currentEntity['children'] = self.__getObjectChildren__(currentEntity['dn'])

            # If children object type should be Array
            if self.childrenObjectType == 'array':
                ###### Append subobject to Array ######
                children.append(currentEntity)

                ###### Increase subobjectId ######
                self.subobjectId += 1
            elif self.childrenObjectType == 'dict':
                ###### Append subobject to Dict ######
                children['dict'][currentEntity['dn']] = currentEntity
                children['dict'][currentEntity['dn']].pop('dn')

                ###### Increase subobjectId ######
                self.subobjectId += 1
        return children

    def __getTreeCount__(self):
        count = 0

        for k, v in enumerate(self.children):
            count += 1
            if 'children' in self.children[k]:
                count += self.__getChildCount__(self.children[k]['children'])
            
        return count

    def __getChildCount__(self, child):
        count = 0
        for k, v in enumerate(child):
            count += 1
            if 'children' in child[k]:
                count += self.__getChildCount__(child[k]['children'])

        return count

    def __getObjectChildren__(self, dn):
        """
        Function to recursively get Object Children
        Returns JSON Dict
        """
        if dn is None:
            raise Exception("LDAPTree.__getObjectChildren__() - ERROR: Distinguished Name is None")

        # If children object type should be Array
        if self.childrenObjectType == 'array':
            result = list()
        else:
            result = dict()

        # Send Query to LDAP Server(s)
        ldapSearch = self.connection.extend.standard.paged_search(
            search_base=dn,
            search_filter=self.ldapFilter,
            search_scope='LEVEL',
            attributes=self.ldapAttributes
        )

        userClasses = [
            'user',
            'person',
            'organizationalPerson',
        ]

        for entry in ldapSearch:
            currentObject = dict()
            # Set sub-object main attributes
            self.subobjectId += 1
            currentObject['id'] = self.subobjectId
            currentObject['name'] = str(entry['dn']).split(',')[0].split('=')[1]
            currentObject['type'] = str(entry['attributes']['objectCategory']).split(',')[0].split('=')[1]
            if currentObject['name'] in LDAP_BUILTIN_OBJECTS or 'builtinDomain' in entry['attributes']['objectClass'] or self.__getCN__(dn) in LDAP_BUILTIN_OBJECTS:
                currentObject['builtin'] = True

            # Set the sub-object children
            if self.childrenObjectType == 'array' and 'children' not in currentObject:
                currentObject['children'] = list()
            elif 'children' not in currentObject:
                currentObject['children'] = dict()

            # Set all other attributes
            for attr in entry['attributes']:
                if attr in self.ldapAttributes or self.ldapAttributes == "*":
                    if attr == self.usernameIdentifier and self.usernameIdentifier in entry['attributes']:
                        allowUsername = False
                        # For class in user classes check if it's in object
                        for cla in userClasses:
                            if cla in entry['attributes']['objectClass']:
                                allowUsername = True
                        if allowUsername == True:
                            value = entry['attributes'][attr][0]
                            currentObject['username'] = value
                    elif attr == 'cn' and 'group' in entry['attributes']['objectClass']:
                        value = entry['attributes'][attr]
                        currentObject['groupname'] = value
                    elif attr == 'objectCategory':
                        value = self.__getCN__(entry['attributes'][attr])
                        currentObject['type'] = value
                    elif attr == 'dn':
                        value = entry['dn']
                    elif attr == 'objectSid' and 'group' in entry['attributes']['objectClass'] and self.__getCN__(dn).lower() != "builtin":
                        try:
                            sid = SID(entry['attributes'][attr])
                            sid = sid.__str__()
                            rid = sid.split("-")[-1]
                            value = sid
                            currentObject['objectRid'] = rid
                        except Exception as e:
                            print("Could not translate SID Byte Array for " + dn)
                            print(e)
                    elif attr not in self.excludedLdapAttributes:
                        if isinstance(entry['attributes'][attr], list) and len(entry['attributes'][attr]) > 1:
                            value = entry['attributes'][attr]
                        else:
                            value = str(entry['attributes'][attr])

                    try:
                        currentObject[attr] = value
                    except Exception as e:
                        print("Exception on key: " + attr)
                        print("Object: " + dn)
                        print(e)

            # Force exclude System folder, has a bunch of objects that aren't useful for administration
            if self.recursive == True and currentObject['type'].lower() in self.containerTypes and self.__getCN__(dn).lower() != "system":
                children = self.__getObjectChildren__(entry['dn'])
            else:
                children = list()

            # Set the sub-object children
            if self.childrenObjectType == 'array' and children:
                currentObject['children'] = children
            elif children:
                currentObject['children'].update(children)

            if not currentObject['children']:
                del currentObject['children']
            result.append(currentObject)
        
        if result:
            return result
        else:
            return None

    def __getCN__(self, dn):
        return str(dn).split(',')[0].split('=')[-1]
