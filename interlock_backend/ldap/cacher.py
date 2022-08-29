################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: interlock_backend.ldap.cacher
# This module saves new settings to constants_cache.py

#---------------------------------- IMPORTS -----------------------------------#
from interlock_backend.ldap import constants
from interlock_backend.ldap import constants_cache
from interlock_backend.settings import BASE_DIR
from json import dumps
from interlock_backend.ldap.encrypt import (
    decrypt,
    encrypt
)
from interlock_backend.ldap.settings_func import normalizeValues
################################################################################

def createFileData():
    filedata =  "# This file is generated automatically by Interlock when saving settings"
    filedata += "\n# Manual changes to it might be lost"
    filedata += "\n################################################################################"
    filedata += "\n#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################"
    filedata += "\n################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################"
    filedata += "\n########################## AND BR CONSULTING S.R.L. ############################"
    filedata += "\n################################################################################"
    filedata += "\n# Module: constants_cache.py"
    filedata += "\n# Contains the latest setting constants for Interlock"
    filedata += "\n"
    filedata += "\n#---------------------------------- IMPORTS -----------------------------------#"
    filedata += "\nfrom interlock_backend.ldap.constants import *"
    filedata += "\nimport ssl"
    filedata += "\n################################################################################"
    filedata += "\n"
    return filedata

def saveToCache(newValues):
    if not isinstance(newValues, dict):
        raise ValueError("saveToCache(): newValues must be a dictionary")

    cacheFile = BASE_DIR+'/interlock_backend/ldap/constants_cache.py'

    filedata = createFileData()

    affectedSettings = list()
    for setting in constants.CMAPS:
        old_val = getattr(constants_cache, setting)
        default_val = getattr(constants, setting)
        if setting == 'LDAP_AUTH_TLS_VERSION':
            old_val = str(default_val).split('.')[-1]
            default_val = str(default_val).split('.')[-1]

        if setting in newValues and 'value' in newValues[setting]:
            set_obj = normalizeValues(setting, newValues[setting])
            set_val = set_obj['value']
            if set_val != default_val or set_val != old_val:
                set_dict = dict()
                set_dict['name'] = setting
                if "password" in setting.lower():
                    set_dict['old_value'] = "********"
                    set_dict['value'] = "********"
                else:
                    set_dict['old_value'] = old_val
                    set_dict['new_value'] = set_val
                # print(set_val)
                # print(default_val)
                affectedSettings.append(set_dict)
        else:
            set_val = default_val

        if setting == 'LDAP_AUTH_CONNECTION_PASSWORD' and constants.PLAIN_TEXT_BIND_PASSWORD != True:
            set_val = encrypt(set_val)

        if setting in map(lambda v: v['name'], affectedSettings):
            # Replace the target string with new value
            if isinstance(set_val, str):
                if setting == 'LDAP_AUTH_TLS_VERSION':
                    line = "%s=ssl.%s" % (setting, set_val)
                else:
                    line = "%s=\"%s\"" % (setting, set_val)
            if isinstance(set_val, int):
                line = "%s=%s" % (setting, set_val)
            elif isinstance(set_val, dict):
                line = "%s=%s" % (setting, dumps(set_val, indent=4))
            elif isinstance(set_val, list) or isinstance(set_val, tuple):
                line = "%s=%s" % (setting, set_val)
            elif not isinstance(set_val, str):
                line = "%s=%s" % (setting, str(set_val))

            # print("\n")
            # print(setting)
            # print(set_val)
            # print(type(set_val))
            # print(line)
            filedata += "\n" + line

    # Write the file
    with open(cacheFile, 'w') as file:
        file.write(filedata)

    return affectedSettings

def resetCacheToDefaults(newValues):
    if not isinstance(newValues, dict):
        raise ValueError("saveToCache(): newValues must be a dictionary")

    cacheFile = BASE_DIR+'/interlock_backend/ldap/constants_cache.py'

    filedata = createFileData()

    # # Write the file
    with open(cacheFile, 'w') as file:
        file.write(filedata)