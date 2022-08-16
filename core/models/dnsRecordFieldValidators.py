from curses.ascii import isascii
import sys
import re
import socket
thismodule = sys.modules[__name__]

FIELD_VALIDATORS = {
    'tstime': None,
    'address': 'ip',
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
    try:
        if re.match(r'^[0-9]+$', str(value)):
            return True
    except Exception as e:
        print(value)
        print(type(value))
        raise e
    return False

def ip_validator(value):
    try:
        socket.inet_aton(str(value))
        return True
    except socket.error:
        return False

def ascii_validator(value):
    if isascii(str(value)):
        return True
    return False