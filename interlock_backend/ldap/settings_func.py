################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: interlock_backend.ldap.settings_func

#---------------------------------- IMPORTS -----------------------------------#
# Core Imports
from core.models.user import User

# Interlock Imports
from interlock_backend.ldap.constants import (
    CMAPS,    
    __dict__ as constantDictionary
)
from interlock_backend.ldap import constants_cache
from interlock_backend.ldap.encrypt import decrypt
from rest_framework import serializers

# Full imports
import traceback
import logging
################################################################################

logger = logging.getLogger(__name__)

def getSettingType(settingKey):
    # Set the Type for the Front-end based on Types in List
    settingType = CMAPS[settingKey]
    if not settingType:
        raise TypeError(f"No type set for {settingKey}")
    return settingType

def normalizeValues(settingKey, settingDict):
    """
    Normalizes values from DB String to whatever type of object it is

    Arguments

    settingKey (STRING) - (The key for the Setting Constant or DB Override)

    settingDict (DICT) - (The dict to normalize)
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
            if not serializers.IntegerField().run_validation(settingDict['value']):
                logger.error(traceback.format_exc())
                raise
            settingDict['value'] = int(settingDict['value'])
        # FLOAT
        elif settingDict['type'] == 'float':
            if not serializers.FloatField().run_validation(settingDict['value']):
                logger.error(traceback.format_exc())
                raise
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
            if not type(serializers.BooleanField().run_validation(settingDict['value'])) == bool:
                logger.error(traceback.format_exc())
                raise

        if settingKey == "LDAP_AUTH_TLS_VERSION":
            settingDict['value'] = str(settingDict['value']).split('.')[-1]
    except:
        raise ValueError(f"Invalid value for {settingKey}: {settingDict['value']} ({type(settingDict['value'])})")
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
            if c == "LDAP_AUTH_CONNECTION_PASSWORD" and data[c]['value'] is not None:
                data[c]['value'] = decrypt(data[c]['value'])

    return data
