from enum import Enum
from interlock_backend.ldap import constants
from interlock_backend.ldap import constants_cache
from interlock_backend.settings import BASE_DIR
from json import dumps
from interlock_backend.ldap.settings_func import normalizeValues

def saveToCache(newValues):
    if not isinstance(newValues, dict):
        raise ValueError("saveToCache(): newValues must be a dictionary")

    cacheFile = BASE_DIR+'/interlock_backend/ldap/constants_cache.py'

    filedata = "from interlock_backend.ldap.constants import *"
    filedata += "\nimport ssl"
    filedata += "\n"

    affectedSettings = list()
    for setting in constants.CMAPS:
        default_val = getattr(constants, setting)
        if setting == 'LDAP_AUTH_TLS_VERSION':
            default_val = str(default_val).split('.')[-1]

        if setting in newValues and 'value' in newValues[setting]:
            set_obj = normalizeValues(setting, newValues[setting])
            set_val = set_obj['value']
            if set_val != default_val:
                print(set_val)
                print(default_val)
                affectedSettings.append(setting)
        else:
            set_val = default_val

        if setting in affectedSettings:
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
                line = "%s=\"%s\"" % (setting, str(set_val))

            # print("\n")
            # print(variable)
            # print(var_value)
            # print(type(var_value))
            # print(line)
            filedata += "\n" + line

    # # Write the file
    with open(cacheFile, 'w') as file:
        file.write(filedata)

    return affectedSettings

def resetCacheToDefaults(newValues):
    if not isinstance(newValues, dict):
        raise ValueError("saveToCache(): newValues must be a dictionary")

    cacheFile = BASE_DIR+'/interlock_backend/ldap/constants_cache.py'

    filedata = "from interlock_backend.ldap.constants import *"
    filedata += "\nimport ssl"
    filedata += "\n"

    # # Write the file
    with open(cacheFile, 'w') as file:
        file.write(filedata)