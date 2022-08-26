################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU GPLv3 #####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: core.models.ldapObject
# Contains the Models for generic LDAP Objects

#---------------------------------- IMPORTS -----------------------------------#
### Django
from django.utils.translation import gettext_lazy as _

### Interlock
from interlock_backend.ldap.constants_cache import *
from interlock_backend.ldap.adsi import LDAP_BUILTIN_OBJECTS, addSearchFilter
from interlock_backend.ldap.securityIdentifier import SID
################################################################################
class LDAPObject():
    """
    ## Interlock LDAP Object Abstraction
    Fetches LDAP Object from a specified DN

    ### Call example
    LDAPTree(**{
        "connection":connection,\n
        "dn":"CN=john,DC=example,DC=com",\n
        ...
    })

    #### Arguments
     - searchBase: (REQUIRED) | DN of Object to Search
     - connection: (REQUIRED) | LDAP Connection Object
     - recursive: (OPTIONAL) | Whether or not the Object should be Recursively searched
     - ldapFilter: (OPTIONAL) | LDAP Formatted Filter
     - ldapAttributes: (OPTIONAL) | LDAP Attributes to Fetch
     - excludedLdapAttributes: (OPTIONAL) | LDAP Attributes to Exclude
    """
    use_in_migrations = False

    def __init__(self, **kwargs):
        if 'connection' not in kwargs:
            raise Exception("LDAP Object requires an LDAP Connection to Initialize")
        if 'dn' not in kwargs and 'ldapFilter' not in kwargs:
            raise Exception("LDAP Object requires a distinguishedName or a valid ldapFilter to search for the object")

        # Set LDAPTree Default Values
        self.name = LDAP_AUTH_SEARCH_BASE
        self.searchBase = LDAP_AUTH_SEARCH_BASE
        self.connection = kwargs.pop('connection')
        self.usernameIdentifier = LDAP_AUTH_USERNAME_IDENTIFIER
        self.subobjectId = 0
        self.excludedLdapAttributes = [
            'objectGUID',
            'objectSid'
        ]
        self.requiredLdapAttributes = [
            'distinguishedName',
            'objectCategory',
            'objectClass',
        ]
        self.containerTypes = [
            'container',
            'organizational-unit'
        ]
        self.userClasses = [
            'user',
            'person',
            'organizationalPerson',
        ]
        self.recursive = False
        self.testFetch = False
        self.ldapAttributes = LDAP_DIRTREE_ATTRIBUTES
        if 'dn' in kwargs:
            self.ldapFilter = addSearchFilter("", "distinguishedName=" + str(kwargs['dn']))

        self.__resetKwargs__(kwargs)

        self.__fetchObject__()

    def __resetKwargs__(self, kwargs):
        # Set passed kwargs from Object Call
        for kw in kwargs:
            setattr(self, kw, kwargs[kw])

        # Set required attributes, these are unremovable from the tree searches
        for attr in self.requiredLdapAttributes:
            if attr not in self.ldapAttributes:
                self.ldapAttributes.append(attr)

    def __getConnection__(self):
        return self.connection

    def __getEntry__(self):
        return self.entry

    def __getObject__(self):
        return self.attributes

    def __fetchObject__(self):
        self.connection.search(
            search_base     = self.searchBase,
            search_filter   = self.ldapFilter,
            search_scope    = 'SUBTREE',
            attributes      = self.ldapAttributes
        )
        searchResult = self.connection.entries
        try:
            self.entry = searchResult[0]
        except Exception as e:
            if not hasattr(self, 'hideErrors') == True:
                print("Search Result")
                print(searchResult)
                print("Error")
                print(e)
            raise ValueError("Error setting LDAP Object Entry Result")

        # Set DN from Abstract Entry object (LDAP3)
        distinguishedName=str(self.entry['distinguishedName'])
        # Set searchResult attributes
        self.attributes = {}
        self.attributes['name'] = str(distinguishedName).split(',')[0].split('=')[1]
        self.attributes['distinguishedName'] = distinguishedName
        self.attributes['type'] = str(self.entry['objectCategory']).split(',')[0].split('=')[1]
        if self.attributes['name'] in LDAP_BUILTIN_OBJECTS or 'builtinDomain' in self.entry['objectClass']:
            self.attributes['builtin'] = True

        for attr_key in self.ldapAttributes:
            attr_value = getattr(self.entry, attr_key)
            str_key = str(attr_key)
            str_value = str(attr_value)
            if attr_key == self.usernameIdentifier:
                self.attributes[attr_key] = str_value
                self.attributes['username'] = str_value
            elif attr_key == 'cn' and 'group' in self.entry['objectClass']:
                value = getattr(self.entry, attr_key)
                self.attributes[attr_key] = str_value
                self.attributes['groupname'] = str_value
            elif attr_key == 'objectSid' and self.__getCN__(distinguishedName).lower() != "builtin":
                value = getattr(self.entry, attr_key)
                try:
                    sid = SID(value)
                    sid = sid.__str__()
                    rid = sid.split("-")[-1]
                    value = sid
                    self.attributes['objectSid'] = sid
                    self.attributes['objectRid'] = rid
                except Exception as e:
                    print("Could not translate SID Byte Array for " + distinguishedName)
                    print(e)
            elif str_key not in self.attributes and str_value != "[]":
                if len(attr_value) > 1:
                    self.attributes[str_key] = list()
                    for k, v in enumerate(attr_value):
                        self.attributes[str_key].append(attr_value[k])
                else:
                    self.attributes[str_key] = str_value

        return self.attributes

    def __ldapAttributes__(self):
        return self.attributes.keys()

    def __getCN__(self, dn):
        return str(dn).split(',')[0].split('=')[-1]
