# Core Imports
from core.models.settings import Setting
from core.models.user import User

# Interlock Imports
from interlock_backend.ldap import constants as ldap_constants

# Full imports
import logging
import ssl
import re
import json

logger = logging.getLogger(__name__)

def normalizeValues(settingKey, settingDict):
    """
    Normalizes values from DB String to whatever type of object it is

    Arguments

    :self: (Object, the mixin)

    :settingKey: (The key for the Setting Constant or DB Override)

    :settingDict: (The dict to normalize)
    """

    # Set the Type for the Front-end based on Types in List
    if 'type' in ldap_constants.SETTINGS_WITH_ALLOWABLE_OVERRIDE[settingKey]:
        settingDict['type'] = ldap_constants.SETTINGS_WITH_ALLOWABLE_OVERRIDE[settingKey]['type']
    else:
        settingDict['type'] = 'string'

    # INT
    if settingDict['type'] == 'integer' and not isinstance(settingDict['value'], int):
        settingDict['value'] = re.sub('\D', '', settingDict['value'])
        settingDict['value'] = int(settingDict['value'])
    # FLOAT
    elif settingDict['type'] == 'float' and not isinstance(settingDict['value'], float):
        settingDict['value'] = re.sub('\D.,', '', settingDict['value'])
        settingDict['value'] = float(settingDict['value'])
    # LIST/ARRAY
    elif (settingDict['type'] == 'list' or settingDict['type'] == 'ldap_uri') and not isinstance(settingDict['value'], list):
        if isinstance(settingDict['value'], str):
            settingDict['value'] = settingDict['value'].replace("'", '"')
            settingDict['value'] = json.loads(settingDict['value'])
        else:
            print(settingKey + ' is not a string or a list, type may be mis-represented in DB')
    # BOOLEAN
    elif settingDict['type'] == 'boolean' and not isinstance(settingDict['value'], bool):
        settingDict['value'] = re.sub('[^a-zA-Z]+', '', settingDict['value'])
    # OBJECT
    elif settingDict['type'] == 'object' and not isinstance(settingDict['value'], object):
        settingDict['value'] = json.load(settingDict['value'])
    # TODO - TUPLE
    # elif settingDict['type'] == 'tuple':
    #     print(settingDict)

        if settingKey == 'EXCLUDE_COMPUTER_ACCOUNTS':
            print(settingDict['value'])

    if settingKey == "LDAP_AUTH_TLS_VERSION":
        settingDict['value'] = str(settingDict['value']).split('.')[-1]
    return settingDict

def getSettingsList(settingList=ldap_constants.SETTINGS_WITH_ALLOWABLE_OVERRIDE):
    data = {}
    
    userQuerySet = User.objects.filter(username = 'admin')
    if userQuerySet.count() > 0:
        defaultAdmin = userQuerySet.get(username = 'admin')
        data['DEFAULT_ADMIN'] = not defaultAdmin.deleted
    else:
        data['DEFAULT_ADMIN'] = False

    # Loop for each constant in the ldap_constants.py file
    for c in ldap_constants.__dict__:
        # If the constant is in the settingList array
        if c in settingList:
            # Init Object/Dict
            data[c] = {}
            querySet = Setting.objects.filter(id = c).exclude(deleted=True)
            # If an override exists in the DB do the following
            if querySet.count() > 0:
                logger.debug(c + "was fetched from DB")
                settingObject = querySet.get(id = c)
                value = settingObject.value
                type = settingObject.type
                data[c]['value'] = value

                data[c] = normalizeValues(c, data[c])
            # If no override exists use the manually setup constant
            else:
                logger.debug(c + "was fetched from Constants File")
                # Set Value
                data[c]['value'] = ldap_constants.__dict__[c]
                # Type is set inside normalizeValues

                data[c] = normalizeValues(c, data[c])
                logger.debug(c)
                logger.debug(ldap_constants.__dict__[c])
                logger.debug(data[c])

    return data

def getSetting(settingKey):
    try:
        querySet = Setting.objects.filter(id = settingKey).exclude(deleted=True)
    except Exception as e:
        print("EXCEPTION FOR DB FILTER:" + settingKey)
        print(e)
    if querySet.count() != 0 and querySet.count() != None:
        logger.debug("Fetching value for "+ settingKey+' from DB')
        try:
            setting = querySet[0]
            setting = normalizeValues(settingKey, setting.__dict__)

            if settingKey == 'LDAP_AUTH_TLS_VERSION':
                return getattr(ssl, setting['value'])
            else:
                return setting['value']
        except Exception as e:
            print("EXCEPTION FOR DB FETCH:" + settingKey)
            print(e)
    else:
        logger.debug("Fetching value for "+ settingKey +' from Constants')
        return ldap_constants.__dict__[settingKey]

LDAP_AUTH_URL = getSetting('LDAP_AUTH_URL')
LDAP_DOMAIN = getSetting('LDAP_DOMAIN')
LDAP_AUTH_USE_TLS = getSetting('LDAP_AUTH_USE_TLS')
LDAP_AUTH_TLS_VERSION = getSetting('LDAP_AUTH_TLS_VERSION')
LDAP_AUTH_SEARCH_BASE = getSetting('LDAP_AUTH_SEARCH_BASE')
LDAP_AUTH_OBJECT_CLASS = getSetting('LDAP_AUTH_OBJECT_CLASS')
EXCLUDE_COMPUTER_ACCOUNTS = getSetting('EXCLUDE_COMPUTER_ACCOUNTS')
LDAP_AUTH_USER_FIELDS = getSetting('LDAP_AUTH_USER_FIELDS')
LDAP_AUTH_USERNAME_IDENTIFIER = getSetting('LDAP_AUTH_USERNAME_IDENTIFIER')
LDAP_AUTH_ACTIVE_DIRECTORY_DOMAIN = getSetting('LDAP_AUTH_ACTIVE_DIRECTORY_DOMAIN')
LDAP_AUTH_CONNECTION_USER_DN = getSetting('LDAP_AUTH_CONNECTION_USER_DN')
LDAP_AUTH_CONNECTION_USERNAME = getSetting('LDAP_AUTH_CONNECTION_USERNAME')
LDAP_AUTH_CONNECTION_PASSWORD = getSetting('LDAP_AUTH_CONNECTION_PASSWORD')
LDAP_AUTH_CONNECT_TIMEOUT = getSetting('LDAP_AUTH_CONNECT_TIMEOUT')
LDAP_AUTH_RECEIVE_TIMEOUT = getSetting('LDAP_AUTH_RECEIVE_TIMEOUT')
ADMIN_GROUP_TO_SEARCH = getSetting('ADMIN_GROUP_TO_SEARCH')
