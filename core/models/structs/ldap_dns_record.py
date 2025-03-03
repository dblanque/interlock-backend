################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: core.models.dns.record
# Contains the Models for DNS Record Types
#
#---------------------------------- IMPORTS -----------------------------------#
from struct import unpack, pack
from core.utils.ipv6 import ipv6_to_integer
from impacket.structure import Structure
from ..types.ldap_dns_record import *
import socket
import datetime
import sys
import logging
################################################################################

logger = logging.getLogger(__name__)

RECORD_MAPPINGS = {
    DNS_RECORD_TYPE_ZERO: {
        'name':'ZERO',
        'class':'DNS_RPC_RECORD_TS',
        'fields':[ 'tstime' ]
    },
    DNS_RECORD_TYPE_A: {
        'name':'A',
        'class':'DNS_RPC_RECORD_A',
        'fields': [ 'address' ],
        'multiRecord': True
    },
    DNS_RECORD_TYPE_AAAA: {
        'name':'AAAA',
        'class':'DNS_RPC_RECORD_AAAA',
        'fields': [ 'ipv6Address' ],
        'multiRecord': True
    },
    DNS_RECORD_TYPE_NS: {
        'name':'NS',
        'class':'DNS_RPC_RECORD_NODE_NAME',
        'fields': [ 'nameNode' ],
        'multiRecord': True
    },
    DNS_RECORD_TYPE_CNAME: {
        'name':'CNAME',
        'class':'DNS_RPC_RECORD_NODE_NAME',
        'fields': [ 'nameNode' ],
        'multiRecord': False
    },
    DNS_RECORD_TYPE_DNAME: {
        'name':'DNAME',
        'class':'DNS_RPC_RECORD_NODE_NAME',
        'fields': [ 'nameNode' ],
        'multiRecord': False
    },
    DNS_RECORD_TYPE_SOA: {
        'name':'SOA',
        'class':'DNS_RPC_RECORD_SOA',
        'mainField': 'namePrimaryServer',
        'fields': [
                    'dwSerialNo',
                    'dwRefresh',
                    'dwRetry',
                    'dwExpire',
                    'dwMinimumTtl',
                    'namePrimaryServer',
                    'zoneAdminEmail'
                ],
        'multiRecord': False
    },
    DNS_RECORD_TYPE_TXT: {
        'name':'TXT',
        'class':'DNS_RPC_RECORD_STRING',
        'fields': [ 'stringData' ],
        'multiRecord': True
    },
    DNS_RECORD_TYPE_X25: {
        'name':'X25',
        'class':'DNS_RPC_RECORD_STRING',
        'fields': [ 'stringData' ],
        'multiRecord': True
    },
    DNS_RECORD_TYPE_ISDN: {
        'name':'ISDN',
        'class':'DNS_RPC_RECORD_STRING',
        'fields': [ 'stringData' ],
        'multiRecord': True
    },
    DNS_RECORD_TYPE_LOC: {
        'name':'LOC',
        'class':'DNS_RPC_RECORD_STRING',
        'fields': [ 'stringData' ],
        'multiRecord': True
    },
    DNS_RECORD_TYPE_HINFO: {
        'name':'HINFO',
        'class':'DNS_RPC_RECORD_STRING',
        'fields': [ 'stringData' ],
        'multiRecord': True
    },
    DNS_RECORD_TYPE_MX: {
        'name':'MX',
        'class':'DNS_RPC_RECORD_NAME_PREFERENCE',
        'mainField': 'nameExchange',
        'fields': [
                    'wPreference',
                    'nameExchange'
                ],
        'multiRecord': True
    },
    DNS_RECORD_TYPE_SIG: {
        'name':'SIG',
        'class': None,
        'fields': []
    },
    DNS_RECORD_TYPE_KEY: {
        'name':'KEY',
        'class': None,
        'fields': []
    },
    DNS_RECORD_TYPE_SRV: {
        'name':'SRV',
        'class':'DNS_RPC_RECORD_SRV',
        'mainField': 'nameTarget',
        'fields': [
                    'wPriority', 
                    'wWeight', 
                    'wPort',
                    'nameTarget'
                ],
        'multiRecord': True
    },
    DNS_RECORD_TYPE_PTR: {
        'name':'PTR',
        'class':'DNS_RPC_RECORD_NODE_NAME',
        'fields': [ 'nameNode' ],
        'multiRecord': False
    },
    DNS_RECORD_TYPE_WINS: {
        'name':'WINS',
        'class': None,
        'fields': []
    },

    # DEPRECATED BY RFCs
    DNS_RECORD_TYPE_MB: {
        'name':'MB',
        'class':'DNS_RPC_RECORD_NODE_NAME',
        'fields': [ 'nameNode' ]
    },
    DNS_RECORD_TYPE_MR: {
        'name':'MR',
        'class':'DNS_RPC_RECORD_NODE_NAME',
        'fields': [ 'nameNode' ]
    },
    DNS_RECORD_TYPE_MG: {
        'name':'MG',
        'class':'DNS_RPC_RECORD_NODE_NAME',
        'fields': [ 'nameNode' ]
    },
    DNS_RECORD_TYPE_MD: {
        'name':'MD',
        'class':'DNS_RPC_RECORD_NODE_NAME',
        'fields': [ 'nameNode' ]
    },
    DNS_RECORD_TYPE_MF: {
        'name':'MF',
        'class':'DNS_RPC_RECORD_NODE_NAME',
        'fields': [ 'nameNode' ]
    },
}

def record_to_dict(record, ts=False):
    thismodule = sys.modules[__name__]

    # For original reference see print_record
    try:
        rtype = RECORD_MAPPINGS[record['Type']]['name']
    except KeyError:
        rtype = 'Unsupported'

    record_dict = {}

    # Check if record is Tombstoned / Inactive
    if ts and len(ts) > 0:
        if ts[0] == True or ts[0] == 'TRUE':
            record_dict['ts'] = True
    else:
        record_dict['ts'] = False

    record_dict['type'] = record['Type']
    record_dict['typeName'] = rtype
    record_dict['serial'] = record['Serial']

    # If the Record Type is Mapped to a Class
    if record['Type'] in RECORD_MAPPINGS:
        # Initialize the class with the record Data key
        data = getattr(thismodule, RECORD_MAPPINGS[record['Type']]['class'])(record['Data'])

        # ! Print class ! #
        logger.debug(getattr(thismodule, RECORD_MAPPINGS[record['Type']]['class']))

        stringFields = [
            'nameNode',
            'nameExchange',
            'nameTarget',
            'namePrimaryServer',
            'zoneAdminEmail'
        ]
        # For each value field mapped for this Record Type set it
        for valueField in RECORD_MAPPINGS[record['Type']]['fields']:
            try:
                if valueField == 'tstime':
                    record_dict[valueField] = data.toDatetime()
                elif valueField == 'address' and record['Type'] == DNS_RECORD_TYPE_A:
                    record_dict[valueField] = data.formatCanonical()
                elif valueField == 'ipv6Address' and record['Type'] == DNS_RECORD_TYPE_AAAA:
                    record_dict[valueField] = data.formatCanonical()
                elif valueField == 'stringData':
                    record_dict[valueField] = data[valueField].toString()
                elif (valueField in stringFields):
                    record_dict[valueField] = data[valueField].toFqdn()
                else:
                    record_dict[valueField] = data[valueField]
            except Exception as e:
                # data.dump()
                print(record_dict)
                print(valueField)
                raise e
    return record_dict

class DNS_RECORD(Structure):
    """
    dnsRecord - used in LDAP
    [MS-DNSP] section 2.3.2.2
    """
    structure = (
        ('DataLength', '<H-Data'),
        ('Type', '<H'),
        ('Version', 'B=5'),
        ('Rank', 'B'),
        ('Flags', '<H=0'),
        ('Serial', '<L'),
        ('TtlSeconds', '>L'),
        ('Reserved', '<L=0'),
        ('TimeStamp', '<L=0'),
        ('Data', ':')
    )

    def __bytedata__(self):
        return self.getData()

    def __str__(self):
        return str(record_to_dict(self))

    def __dict__(self):
        return record_to_dict(self)

    def __getTTL__(self):
        return self['TtlSeconds']

# Note that depending on whether we use RPC or LDAP all the DNS_RPC_XXXX
# structures use DNS_RPC_NAME when communication is over RPC,
# but DNS_COUNT_NAME is the way they are stored in LDAP.
#
# Since LDAP is the primary goal of this script we use that, but for use
# over RPC the DNS_COUNT_NAME in the structures must be replaced with DNS_RPC_NAME,
# which is also consistent with how MS-DNSP describes it.

class DNS_RPC_NAME(Structure):
    """
    DNS_RPC_NAME
    Used for FQDNs in RPC communication.
    MUST be converted to DNS_COUNT_NAME for LDAP
    [MS-DNSP] section 2.2.2.2.1
    """
    structure = (
        ('cchNameLength', 'B-dnsName'),
        ('dnsName', ':')
    )

    def toString(self):
        labels = ""
        for i in range(self['cchNameLength']):
            # Convert byte array of ASCII or UTF-8 data from (single?) 
            # byte character.
            labels = labels + chr(self['dnsName'][i])
        return labels

    def toRPCName(self, valueString):
        length = len(valueString)
        dnsName = []
        for i in range(length):
            # Convert character to ASCII single byte character.
            dnsName.append(ord(valueString[i]))
        lengthToPack = pack('B', length)
        self['cchNameLength'] = lengthToPack
        self['dnsName'] = bytes(dnsName)

class DNS_COUNT_NAME(Structure):
    """
    DNS_COUNT_NAME
    Used for FQDNs in LDAP communication
    MUST be converted to DNS_RPC_NAME for RPC communication
    [MS-DNSP] section 2.2.2.2.2
    """

    structure = (
        ('Length', 'B-RawName'),
        ('LabelCount', 'B'),
        ('RawName', ':')
    )

    def insert_field_to_struct(self, fieldName=None, fieldStructVal=None):
        """
        Insert a field into the byte structure before the defaults
        """
        oldStruct = self.structure
        self.structure = [(fieldName, fieldStructVal)]
        self.structure.extend(list(oldStruct))
        self.structure = tuple(self.structure)

    def setField(self, fieldName, value, type=int):
        """
        Set value for an inserted field in the structure
        You may cast to a specific type, default is int
        - fieldName: The name of the field
        - value: The value of the field
        - type: The type to cast (default: int)
        """
        self[fieldName] = type(value)

    def toFqdn(self):
        ind = 0
        labels = []
        for i in range(self['LabelCount']):
            try:
                nextlen = unpack('B', self['RawName'][ind:ind+1])[0]
                labels.append(self['RawName'][ind+1:ind+1+nextlen].decode('utf-8'))
                ind += nextlen + 1
            except Exception as e:
                print("Unable to UNPACK Raw Name in DNS Record")
                print('Length (' + str(type(self['Length'])) + '): ')
                print(self['Length'])
                print('LabelCount (' + str(type(self['LabelCount'])) + '): ')
                print(self['LabelCount'])
                print('RawName (' + str(type(self['RawName'])) + '): ')
                print(self['RawName'])
                raise e

        # For the final dot
        labels.append('')
        return '.'.join(labels)

    def toCountName(self, valueString, addNullAtEnd=True):
        # Structure:
        # String -> FQDN -> 1-byte Label Length COUNT for the subsequent label

        length = len(valueString)
        splitString = valueString.rstrip('.').split('.')
        labelCount = len(splitString)
        if labelCount <= 0:
            labelCount = 0
        newString = bytes()
        for i in range(labelCount):
            newString += pack('B', len(splitString[i])) + (bytes(splitString[i], 'utf-8'))

        # Add 1 to Length as it must include the NULL Terminator Byte
        self['Length'] = length + 1
        self['LabelCount'] = labelCount
        try:
            if addNullAtEnd == True:
                self['RawName'] = newString + b'\x00'
            else:
                self['RawName'] = newString
        except Exception as e:
            print(e)
            raise Exception("Error setting RawName key in Data Structure")

        if len(self['RawName']) > 256:
            print(self['RawName'])
            raise ValueError("Raw Name Length cannot be more than 256")

        # print('Length')
        # print(self['Length'])
        # print(type(self['Length']))
        # print('LabelCount')
        # print(self['LabelCount'])
        # print(type(self['LabelCount']))
        # print('RawName')
        # print(self['RawName'])
        # print(type(self['RawName']))


class DNS_RPC_NODE(Structure):
    """
    DNS_RPC_NODE
    Defines a structure used as a header for a list of DNS_RPC_RECORD structs
    [MS-DNSP] section 2.2.2.2.3
    """
    structure = (
        ('wLength', '>H'),
        ('wRecordCount', '>H'),
        ('dwFlags', '>L'),
        ('dwChildCount', '>L'),
        ('dnsNodeName', ':')
    )

class DNS_RPC_RECORD_A(Structure):
    """
    DNS_RPC_RECORD_A
    Contains an IPv4 Address
    [MS-DNSP] section 2.2.2.2.4.1
    """
    structure = (
        ('address', ':'),
    )

    def formatCanonical(self):
        """
        formatCanonical (IPv4)
        Returns IPv4 Bytes as String Address
        """
        return socket.inet_ntop(socket.AF_INET, self['address'])

    def fromCanonical(self, canonical):
        """
        fromCanonical (IPv4)
        Returns IPv4 String Address as Bytes
        """
        self['address'] = socket.inet_pton(socket.AF_INET, canonical)


class DNS_RPC_RECORD_NODE_NAME(Structure):
    """
    DNS_RPC_RECORD_NODE_NAME

    This Structure contains information about any of the following DNS Types:

    - DNS_TYPE_PTR
    - DNS_TYPE_NS
    - DNS_TYPE_CNAME
    - DNS_TYPE_DNAME
    - DNS_TYPE_MB
    - DNS_TYPE_MR
    - DNS_TYPE_MG
    - DNS_TYPE_MD
    - DNS_TYPE_MF

    [MS-DNSP] section 2.2.2.2.4.2
    """
    structure = (
        ('nameNode', ':', DNS_COUNT_NAME),
    )

class DNS_RPC_RECORD_SOA(Structure):
    """
    DNS_RPC_RECORD_SOA
    This structure contains information for a Start Of Authority Record
    [MS-DNSP] section 2.2.2.2.4.3
    """
    structure = (
        ('dwSerialNo', '>L'),
        ('dwRefresh', '>L'),
        ('dwRetry', '>L'),
        ('dwExpire', '>L'),
        ('dwMinimumTtl', '>L'),
        ('namePrimaryServer', ':', DNS_COUNT_NAME),
        ('zoneAdminEmail', ':', DNS_COUNT_NAME)
    )

    def setField(self, fieldName, value):
        self[fieldName] = int(value)

    def addCountName(self, valueString):
        countName = DNS_COUNT_NAME()
        countName.toCountName(valueString=valueString, addNullAtEnd=True)
        return countName.getData()

class DNS_RPC_RECORD_NULL(Structure):
    """
    DNS_RPC_RECORD_NULL

    Contains information for any record for which there is no more
    specific DNS_RPC_RECORD structure.

    [MS-DNSP] section 2.2.2.2.4.4
    """
    structure = (
        ('bData', ':'),
    )

class DNS_RPC_RECORD_STRING(Structure):
    """
    DNS_RPC_RECORD_STRING

    This Structure specifies information about a DNS record of
    any of the following types:
    - DNS_TYPE_HINFO
    - DNS_TYPE_ISDN
    - DNS_TYPE_TXT
    - DNS_TYPE_X25
    - DNS_TYPE_LOC

    [MS-DNSP] section 2.2.2.2.4.6
    """
    structure = (
        ('stringData', ':', DNS_RPC_NAME),
    )

# TODO
##   DNS_RPC_RECORD_MAIL_ERROR                  | 2.2.2.2.4.7

class DNS_RPC_RECORD_NAME_PREFERENCE(Structure):
    """
    DNS_RPC_RECORD_NAME_PREFERENCE

    This Structure specifies information about a DNS record of
    any of the following types:

    - DNS_TYPE_MX
    - DNS_TYPE_AFSDB
    - DNS_TYPE_RT

    [MS-DNSP] section 2.2.2.2.4.8
    """
    structure = (
        ('wPreference', '>H'),
        ('nameExchange', ':', DNS_COUNT_NAME)
    )

class DNS_RPC_RECORD_SIG(Structure):
    """
    DNS_RPC_RECORD_SIG

    This structure contains information about cryptographic public key 
    signatures as specified in section 4 of RFC-2535

    [MS-DNSP] section 2.2.2.2.4.9
    """
    structure = (
        ('wTypeCovered', '>H'), # 2 bytes - Unsigned Short
        ('chAlgorithm', '>B'), # 1 byte - Unsigned Char
        ('chLabelCount', '>B'), # 1 byte - Unsigned Char
        ('dwOriginalTtl', '>L'), # 4 bytes - Unsigned Long
        ('dwSigExpiration', '>L'), # 4 bytes - Unsigned Long
        ('dwSigInception', '>L'), # 4 bytes - Unsigned Long
        ('wKeyTag', '>H'), # 2 bytes - Unsigned Short
        ('nameSigner', ':', DNS_COUNT_NAME), # Variable
        ('SignatureInfo', ':'), # Variable
    )

# TODO
## DNS_RPC_RECORD_NSEC      | 2.2.2.2.4.11
## DNS_RPC_RECORD_DS        | 2.2.2.2.4.12
## DNS_RPC_RECORD_KEY       | 2.2.2.2.4.13
## DNS_RPC_RECORD_DHCID     | 2.2.2.2.4.14
## DNS_RPC_RECORD_DNSKEY    | 2.2.2.2.4.15
class DNS_RPC_RECORD_AAAA(Structure):
    """
    DNS_RPC_RECORD_AAAA
    [MS-DNSP] section 2.2.2.2.4.16
    """
    structure = (
        ('ipv6Address', '!16s'),
    )

    def formatCanonical(self):
        """
        formatCanonical (IPv6)
        Returns IPv6 Bytes as String Address
        """
        return socket.inet_ntop(socket.AF_INET6, self['ipv6Address'])
        # return self['ipv6Address']

    def fromCanonical(self, canonical):
        """
        fromCanonical (IPv6)
        Returns IPv6 String Address without separators
        """
        self['ipv6Address'] = socket.inet_pton(socket.AF_INET6, canonical)
        # self['ipv6Address'] = str(canonical).replace(':','')

# TODO
## DNS_RPC_RECORD_NXT       | 2.2.2.2.4.17

class DNS_RPC_RECORD_SRV(Structure):
    """
    DNS_RPC_RECORD_SRV
    [MS-DNSP] section 2.2.2.2.4.18
    """
    structure = (
        ('wPriority', '>H'),
        ('wWeight', '>H'),
        ('wPort', '>H'),
        ('nameTarget', ':', DNS_COUNT_NAME)
    )

    def setField(self, fieldName, value):
        self[fieldName] = int(value)

    def addCountName(self, valueString):
        countName = DNS_COUNT_NAME()
        countName.toCountName(valueString=valueString, addNullAtEnd=True)
        return countName.getData()

# TODO
## DNS_RPC_RECORD_ATMA      | 2.2.2.2.4.19
## DNS_RPC_RECORD_NAPTR     | 2.2.2.2.4.20
## DNS_RPC_RECORD_WINS      | 2.2.2.2.4.21
## DNS_RPC_RECORD_WINSR     | 2.2.2.2.4.22
class DNS_RPC_RECORD_TS(Structure):
    """
    DNS_RPC_RECORD_TS
    [MS-DNSP] section 2.2.2.2.4.23
    """
    structure = (
        ('entombedTime', '<Q'),
    )
    def toDatetime(self):
        microseconds = self['entombedTime'] / 10.
        return datetime.datetime(1601,1,1) + datetime.timedelta(microseconds=microseconds)

# TODO
## DNS_RPC_RECORD_NSEC3     | 2.2.2.2.4.24
## DNS_RPC_RECORD_NSEC3PARAM| 2.2.2.2.4.25
## DNS_RPC_RECORD_TLSA      | 2.2.2.2.4.26
## DNS_RPC_RECORD_UNKNOWN   | 2.2.2.2.4.27
