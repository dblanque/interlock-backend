# Core Imports
from core.models.settings_model import Setting
from core.models.user import User

# Interlock Imports
from interlock_backend.ldap.constants import (
    SETTINGS_WITH_ALLOWABLE_OVERRIDE,
    __dict__ as constantDictionary
)
# Full imports
import logging
import ssl
import re
import json

logger = logging.getLogger(__name__)

class SettingsList():
    def __init__(self,**kwargs):
        super(SettingsList, self).__init__()
        self.name = 'SettingsList'
        for c in constantDictionary:
            if c in SETTINGS_WITH_ALLOWABLE_OVERRIDE:
                setattr(self, c, getSetting(c))
            else:
                setattr(self, c, constantDictionary[c])

def normalizeValues(settingKey, settingDict):
    """
    Normalizes values from DB String to whatever type of object it is

    Arguments

    :self: (Object, the mixin)

    :settingKey: (The key for the Setting Constant or DB Override)

    :settingDict: (The dict to normalize)
    """

    settingDict['type'] = getSettingType(settingKey)

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
        if settingDict['value'] == 'True' or settingDict['value'] == 'true':
            settingDict['value'] = True
        else:
            settingDict['value'] = False
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

def getSettingsList(settingList=SETTINGS_WITH_ALLOWABLE_OVERRIDE, listFormat='backend'):
    """Returns a Dictionary with the current setting values in the system

        Arguments:

        settingList (STRING) - Default is SETTINGS_WITH_ALLOWABLE_OVERRIDE

        listFormat (STRING) - frontend or backend

        BACKEND - Returns Object
        FRONTEND - Returns Dict with values and types
    """

    if listFormat.lower() == 'backend' or listFormat is None:
        data = SettingsList()
        for c in constantDictionary:
            if c in settingList:
                setattr(data, c, getSetting(c))
            else:
                setattr(data, c, constantDictionary[c])
        return data

    data = {}
    userQuerySet = User.objects.filter(username = 'admin')
    if userQuerySet.count() > 0:
        defaultAdmin = userQuerySet.get(username = 'admin')
        data['DEFAULT_ADMIN'] = not defaultAdmin.deleted
    else:
        data['DEFAULT_ADMIN'] = False

    # Loop for each constant in the ldap_constants.py file
    for c in constantDictionary:
        # If the constant is in the settingList array
        if c in settingList:
            # Init Object/Dict
            data[c] = {}

            data[c]['type'] = getSettingType(c)
            data[c]['value'] = getSetting(c)

            if c == 'LDAP_AUTH_TLS_VERSION':
                data[c]['value'] = str(data[c]['value'])
                data[c]['value'] = data[c]['value'].split('.')[-1]

    # print(data)
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
        return constantDictionary[settingKey]

def getSettingType(settingKey):
    # Set the Type for the Front-end based on Types in List
    if 'type' in SETTINGS_WITH_ALLOWABLE_OVERRIDE[settingKey]:
        type = SETTINGS_WITH_ALLOWABLE_OVERRIDE[settingKey]['type']
    else:
        type = 'string'
    return type
