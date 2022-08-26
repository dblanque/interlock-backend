from enum import Enum
import interlock_backend.ldap.constants as constants
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

    for variable in constants.CMAPS:
        if variable in newValues and 'value' in newValues[variable]:
            var_obj = normalizeValues(variable, newValues[variable])
            var_value = var_obj['value']
        else:
            var_value = getattr(constants, variable)

        # Replace the target string with new value
        if isinstance(var_value, str):
            if variable == 'LDAP_AUTH_TLS_VERSION':
                print(var_value)
                line = "%s=ssl.%s" % (variable, var_value)
            else:
                line = "%s=\"%s\"" % (variable, var_value)
        if isinstance(var_value, int):
            line = "%s=%s" % (variable, var_value)
        elif isinstance(var_value, dict):
            line = "%s=%s" % (variable, dumps(var_value, indent=4))
        elif isinstance(var_value, list) or isinstance(var_value, tuple):
            line = "%s=%s" % (variable, var_value)
        elif not isinstance(var_value, str):
            line = "%s=\"%s\"" % (variable, str(var_value))

        # print("\n")
        # print(variable)
        # print(var_value)
        # print(type(var_value))
        # print(line)
        filedata += "\n" + line

    # # Write the file
    with open(cacheFile, 'w') as file:
        file.write(filedata)

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