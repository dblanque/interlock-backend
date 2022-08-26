# Core Imports
from core.models.user import User

# Interlock Imports
from interlock_backend.ldap.constants import (
    CMAPS,    
    __dict__ as constantDictionary
)
from interlock_backend.ldap import constants_cache
# Full imports
import logging

logger = logging.getLogger(__name__)

def getSettingType(settingKey):
    # Set the Type for the Front-end based on Types in List
    if 'type' in CMAPS[settingKey]:
        type = CMAPS[settingKey]['type']
    else:
        type = 'string'
    return type

def normalizeValues(settingKey, settingDict):
    """
    Normalizes values from DB String to whatever type of object it is

    Arguments

    :self: (Object, the mixin)

    :settingKey: (The key for the Setting Constant or DB Override)

    :settingDict: (The dict to normalize)
    """

    try:
        settingDict['type'] = getSettingType(settingKey)
    except Exception as e:
        print(settingKey)
        raise e

    listTypes = [ 'list', 'object', 'ldap_uri', 'array', 'tuple' ]

    try:
        # INT
        if settingDict['type'] == 'integer':
            settingDict['value'] = int(settingDict['value'])
        # FLOAT
        elif settingDict['type'] == 'float':
            settingDict['value'] = float(settingDict['value'])
        # LIST/ARRAY OR OBJECT
        elif (settingDict['type'] in listTypes):
            settingDict['value'] = settingDict['value']
        # BOOLEAN
        elif settingDict['type'] == 'boolean':
            if settingDict['value'] == "1" or settingDict['value'] == 1 or settingDict['value'] == 'true' or settingDict['value'] == 'True':
                settingDict['value'] = True
            else:
                settingDict['value'] = False

        if settingKey == "LDAP_AUTH_TLS_VERSION":
            settingDict['value'] = str(settingDict['value']).split('.')[-1]
    except:
        raise ValueError("Invalid value for %s: %s (%s)" % (settingKey, settingDict['value'], type(settingDict['value'])))
    return settingDict

def getSettingsList(settingList=CMAPS):
    """Returns a Dictionary with the current setting values in the system

        Arguments:

        settingList (STRING) - Default is CMAPS

        listFormat (STRING) - frontend or backend

        BACKEND - Returns Object
        FRONTEND - Returns Dict with values and types
    """

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
            data[c]['value'] = getattr(constants_cache, c)

            if c == 'LDAP_AUTH_TLS_VERSION':
                data[c]['value'] = str(data[c]['value'])
                data[c]['value'] = data[c]['value'].split('.')[-1]

    return data
