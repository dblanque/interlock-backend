import sys
import re
thismodule = sys.modules[__name__]

FIELD_VALIDATORS = {
    'tstime': None,
    'address': None,
    'nameNode': None,
    'dwSerialNo': 'natural',
    'dwRefresh': 'natural',
    'dwRetry': 'natural',
    'dwExpire': 'natural',
    'dwMinimumTtl': 'natural',
    'namePrimaryServer': None,
    'zoneAdminEmail': None,
    'stringData': None,
    'wPreference': 'natural',
    'nameExchange': None,
    'wPriority': 'natural', 
    'wWeight': 'natural', 
    'wPort': 'natural',
    'nameTarget': None
}

def natural_validator(value):
    if re.match(r'^[0-9]+$', value):
        return True
    return False