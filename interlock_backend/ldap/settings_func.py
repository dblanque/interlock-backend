# Core Imports
from typing import Literal
from core.models.settings_model import Setting
from core.exceptions import settings_exc as exc_settings
from core.models.user import User

# Interlock Imports
from interlock_backend.ldap.constants import (
    SETTINGS_WITH_ALLOWABLE_OVERRIDE,
    DISABLE_SETTING_OVERRIDES,
    __dict__ as constantDictionary
)
# Full imports
import logging
import ssl
import inspect
from django.db import connection

logger = logging.getLogger(__name__)

def settings_table_exists():
    db_tables = connection.introspection.table_names()
    if 'core_setting' in db_tables:
        return True
    return False

def getSetting(settingKey):
    valueFields = [
        'value',
        'value_bool',
        'value_json',
        'value_int',
        'value_float'
    ]

    if not settings_table_exists():
        return constantDictionary[settingKey]

    try:
        querySet = Setting.objects.filter(id = settingKey).exclude(deleted=True)
    except Exception as e:
        print("EXCEPTION FOR DB FILTER:" + settingKey)
        print(e)
    if querySet.count() != 0 and querySet.count() != None and DISABLE_SETTING_OVERRIDES != True:
        logger.debug("Fetching value for "+ settingKey+' from DB')
        try:
            setting = querySet[0]
            # setting = normalizeValues(settingKey, setting.__dict__)

            if settingKey == 'LDAP_AUTH_TLS_VERSION':
                return getattr(ssl, setting.value)
            else:
                for field in valueFields:
                    fieldValue = getattr(setting, field)
                    if fieldValue is not None and fieldValue != "":
                        if settingKey == 'LDAP_AUTH_SEARCH_BASE':
                            normalizedSearchBase = fieldValue.replace('dc=', 'DC=')
                            normalizedSearchBase = normalizedSearchBase.replace('cn=', 'CN=')
                            return normalizedSearchBase
                        else:
                            return fieldValue
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

def normalizeValues(settingKey, settingDict):
    """
    Normalizes values from DB String to whatever type of object it is

    Arguments

    :self: (Object, the mixin)

    :settingKey: (The key for the Setting Constant or DB Override)

    :settingDict: (The dict to normalize)
    """

    settingDict['type'] = getSettingType(settingKey)
    listTypes = [ 'list', 'object', 'ldap_uri', 'array', 'tuple' ]

    # INT
    if settingDict['type'] == 'integer':
        settingDict['value_int'] = settingDict['value']
    # FLOAT
    elif settingDict['type'] == 'float':
        settingDict['value_float'] = settingDict['value']
    # LIST/ARRAY OR OBJECT
    elif (settingDict['type'] in listTypes):
        settingDict['value_json'] = settingDict['value']
    # BOOLEAN
    elif settingDict['type'] == 'boolean':
        settingDict['value_bool'] = settingDict['value']
    # TODO - TUPLE
    # elif settingDict['type'] == 'tuple':
    #     print(settingDict)

    if settingKey == "LDAP_AUTH_TLS_VERSION":
        settingDict['value'] = str(settingDict['value']).split('.')[-1]
    return settingDict

def getSettingsList(settingList=SETTINGS_WITH_ALLOWABLE_OVERRIDE):
    """Returns a Dictionary with the current setting values in the system

        Arguments:

        settingList (STRING) - Default is SETTINGS_WITH_ALLOWABLE_OVERRIDE

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
            data[c]['value'] = getSetting(c)

            if c == 'LDAP_AUTH_TLS_VERSION':
                data[c]['value'] = str(data[c]['value'])
                data[c]['value'] = data[c]['value'].split('.')[-1]

    return data
class SettingsList(object):
    LDAP_AUTH_URL = Literal
    LDAP_DOMAIN = Literal
    LDAP_AUTH_USE_TLS = Literal
    LDAP_AUTH_TLS_VERSION = Literal
    LDAP_AUTH_SEARCH_BASE = Literal
    LDAP_SCHEMA_NAMING_CONTEXT = Literal
    LDAP_AUTH_OBJECT_CLASS = Literal
    LDAP_GROUP_TYPES = Literal
    LDAP_GROUP_SCOPES = Literal
    EXCLUDE_COMPUTER_ACCOUNTS = Literal
    LDAP_AUTH_USER_FIELDS = Literal
    LDAP_AUTH_USERNAME_IDENTIFIER = Literal
    LDAP_AUTH_USER_LOOKUP_FIELDS = Literal
    LDAP_AUTH_CLEAN_USER_DATA = Literal
    LDAP_AUTH_SYNC_USER_RELATIONS = Literal
    LDAP_AUTH_FORMAT_SEARCH_FILTERS = Literal
    LDAP_AUTH_FORMAT_USERNAME = Literal
    LDAP_AUTH_ACTIVE_DIRECTORY_DOMAIN = Literal
    LDAP_AUTH_CONNECTION_USER_DN = Literal
    LDAP_AUTH_CONNECTION_USERNAME = Literal
    LDAP_AUTH_CONNECTION_PASSWORD = Literal
    LDAP_AUTH_CONNECT_TIMEOUT = Literal
    LDAP_AUTH_RECEIVE_TIMEOUT = Literal
    ADMIN_GROUP_TO_SEARCH = Literal
    LDAP_DIRTREE_OU_FILTER = Literal
    LDAP_DIRTREE_CN_FILTER = Literal
    LDAP_DIRTREE_ATTRIBUTES = Literal
    LDAP_LOG_READ = Literal
    LDAP_LOG_CREATE = Literal
    LDAP_LOG_UPDATE = Literal
    LDAP_LOG_DELETE = Literal
    LDAP_LOG_OPEN_CONNECTION = Literal
    LDAP_LOG_CLOSE_CONNECTION = Literal
    LDAP_LOG_LOGIN = Literal
    LDAP_LOG_LOGOUT = Literal
    LDAP_LOG_MAX = Literal

    def __init__(self,**kwargs):
        self.name = 'SettingsList'
        if 'search' in kwargs:
            for arg in kwargs['search']:
                if arg in SETTINGS_WITH_ALLOWABLE_OVERRIDE:
                    setattr(self, arg, getSetting(arg))
                else:
                    setattr(self, arg, constantDictionary[arg])
        else:
            for setting in constantDictionary:
                if setting in SETTINGS_WITH_ALLOWABLE_OVERRIDE:
                    setattr(self, setting, getSetting(setting))
                else:
                    setattr(self, setting, constantDictionary[setting])

    def __getattribute__(self, attr):
        result = super(SettingsList, self).__getattribute__(attr)
        if result == Literal:
            message = "%s could not be fetched as it's not in the search list" % (attr)
            caller = inspect.getframeinfo(inspect.stack()[1][0])
            print(message)
            print("Traceback: %s at line %s" % (caller.filename, caller.lineno + 1))
            raise exc_settings.SettingNotInList
        else:
            return result
