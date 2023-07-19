################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: core.models.dns.validators
# Contains the Validators for DNS Records

#---------------------------------- IMPORTS -----------------------------------#
import sys
import logging
import re
import socket
from core.utils.ipv6 import ipv6_to_integer
thismodule = sys.modules[__name__]
logger = logging.getLogger(__name__)

FIELD_VALIDATORS = {
    'tstime': None,
    'address': 'ipv4',
    'ipv6Address': 'ipv6',
    'nameNode': 'canonicalHostname',
    'dwSerialNo': 'natural',
    'dwRefresh': 'natural',
    'dwRetry': 'natural',
    'dwExpire': 'natural',
    'dwMinimumTtl': 'natural',
    'namePrimaryServer': 'canonicalHostname',
    'zoneAdminEmail': 'canonicalHostname',
    'stringData': 'ascii',
    'wPreference': 'natural',
    'nameExchange': 'canonicalHostname',
    'wPriority': 'natural', 
    'wWeight': 'natural', 
    'wPort': 'natural',
    'nameTarget': 'canonicalHostname'
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

def canonicalHostname_validator(value):
    pattern = r'^(((?:[a-zA-Z0-9-.]){2,61}(?:\.[a-zA-Z.]{3,})+|(?:[a-zA-Z0-9-]){2,64})+.)?$'
    try:
        if re.match(pattern, str(value)):
            return True
    except Exception as e:
        print(value)
        print(type(value))
        raise e
    return False

def domain_validator(value):
    pattern = r'^(((?:[a-zA-Z0-9-.]){2,61}(?:\.[a-zA-Z]{2,})+|(?:[a-zA-Z0-9-]){2,64}))?$'
    try:
        if re.match(pattern, str(value)):
            return True
    except Exception as e:
        print(value)
        print(type(value))
        raise e
    return False

def ipv4_validator(value):
    try:
        socket.inet_aton(str(value))
    except socket.error:
        return False
    return True

def ipv6_validator(value):
    try:
        ipv6_to_integer(value)
    except socket.error:
        return False
    return True

def ascii_validator(value):
    # https://stackoverflow.com/questions/35889505/check-that-a-string-contains-only-ascii-characters
    isAscii = lambda s: re.match('^[\x00-\x7F]+$', s) != None
    return isAscii(value)