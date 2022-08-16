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
    if re.match(r'^[0-9]+$', value):
        return True
    return False

def ip_validator(value):
    try:
        socket.inet_aton(value)
        return True
    except socket.error:
        return False

def ascii_validator(value):
    if isascii(value):
        return True
    return False