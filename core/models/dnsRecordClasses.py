from struct import unpack, pack
from impacket.structure import Structure
from .dnsRecordTypes import *
import socket
import datetime

RECORD_TYPE_MAPPING = {
    DNS_RECORD_TYPE_ZERO: 'ZERO',
    DNS_RECORD_TYPE_A: 'A',
    DNS_RECORD_TYPE_NS: 'NS',
    DNS_RECORD_TYPE_CNAME: 'CNAME',
    DNS_RECORD_TYPE_SOA: 'SOA',
    DNS_RECORD_TYPE_TXT: 'TXT',
    DNS_RECORD_TYPE_X25: 'X25',
    DNS_RECORD_TYPE_ISDN: 'ISDN',
    DNS_RECORD_TYPE_MX: 'MX',
    DNS_RECORD_TYPE_SIG: 'SIG',
    DNS_RECORD_TYPE_KEY: 'KEY',
    DNS_RECORD_TYPE_AAAA: 'AAAA',
    DNS_RECORD_TYPE_SRV: 'SRV',
    DNS_RECORD_TYPE_PTR: 'PTR',
    DNS_RECORD_TYPE_WINS: 'WINS'
}

RECORD_CLASS_MAPPING = {
    #! DNS_RECORD_TYPE_ZERO: ?,
    DNS_RECORD_TYPE_A: 'DNS_RPC_RECORD_A',
    # DNS_RECORD_TYPE_NS: 'DNS_RPC_RECORD_NODE_NAME',
    # DNS_RECORD_TYPE_CNAME: 'DNS_RPC_RECORD_NODE_NAME',
    # DNS_RECORD_TYPE_SOA: 'DNS_RPC_RECORD_SOA',
    # DNS_RECORD_TYPE_TXT: 'DNS_RPC_RECORD_STRING',
    #! DNS_RECORD_TYPE_X25: 'X25',
    #! DNS_RECORD_TYPE_ISDN: 'ISDN',
    # DNS_RECORD_TYPE_MX: 'DNS_RPC_RECORD_NAME_PREFERENCE',
    #! DNS_RECORD_TYPE_SIG: 'SIG',
    #! DNS_RECORD_TYPE_KEY: 'KEY',
    # DNS_RECORD_TYPE_AAAA: 'DNS_RPC_RECORD_AAAA',
    # DNS_RECORD_TYPE_SRV: 'DNS_RPC_RECORD_SRV',
    # DNS_RECORD_TYPE_PTR: 'DNS_RPC_RECORD_NODE_NAME',
    #! DNS_RECORD_TYPE_WINS: ?
}

RECORD_MULTIRECORD_VALID_TYPES = [ 1 ]

# Main Value Field should be index 0
RECORD_VALUE_MAPPING = {
    # A Record
    DNS_RECORD_TYPE_A: [ 'address' ],
    # NS Record
    DNS_RECORD_TYPE_NS: [ 'nameNode' ],
    # CNAME Record
    DNS_RECORD_TYPE_CNAME: [ 'nameNode' ],
    # SOA Record
    DNS_RECORD_TYPE_SOA: [
        'namePrimaryServer',
        'dwSerialNo',
        'dwRefresh',
        'dwRetry',
        'dwExpire',
        'dwMinimumTtl',
        'zoneAdminEmail'
        ],
    # MX Record
    DNS_RECORD_TYPE_MX: [
            'nameExchange',
            'wPreference'
        ],
    # TXT Record
    DNS_RECORD_TYPE_TXT: [ 'stringData' ],
    # SRV Record
    DNS_RECORD_TYPE_SRV: [
            'nameTarget',
            'wPriority', 
            'wWeight', 
            'wPort'
        ],
    # PTR Record
    DNS_RECORD_TYPE_PTR: [],
    # WINS Record
    DNS_RECORD_TYPE_WINS: []
}

def record_to_dict(record, ts=False):
    # For original reference see print_record
    try:
        rtype = RECORD_TYPE_MAPPING[record['Type']]
    except KeyError:
        rtype = 'Unsupported'

    record_dict = dict()

    # Check if record is Tombstoned / Inactive
    if ts and len(ts) > 0:
        if ts[0] == True or ts[0] == 'TRUE':
            record_dict['ts'] = True
    else:
        record_dict['ts'] = False

    record_dict['type'] = record['Type']
    record_dict['typeName'] = rtype
    record_dict['serial'] = record['Serial']
    if record['Type'] == 0:
        tstime = DNS_RPC_RECORD_TS(record['Data'])
        record_dict['tstime'] = tstime.toDatetime()
    # A record
    if record['Type'] == 1:
        address = DNS_RPC_RECORD_A(record['Data'])
        record_dict['address'] = address.formatCanonical()
    # NS record or CNAME record
    if record['Type'] == 2 or record['Type'] == 5:
        address = DNS_RPC_RECORD_NODE_NAME(record['Data'])
        record_dict['nameNode'] = address['nameNode'].toFqdn()
    # MX record
    if record['Type'] == 15:
        address = DNS_RPC_RECORD_NAME_PREFERENCE(record['Data'])
        record_dict['wPreference'] = address['wPreference']
        record_dict['nameExchange'] = address['nameExchange'].toFqdn()
    # TXT record
    if record['Type'] == 16:
        address = DNS_RPC_RECORD_STRING(record['Data'])
        record_dict['stringData'] = address['stringData'].toString()
    # SRV record
    if record['Type'] == 33:
        record_data = DNS_RPC_RECORD_SRV(record['Data'])
        record_dict['wPriority'] = record_data['wPriority']
        record_dict['wWeight'] = record_data['wWeight']
        record_dict['wPort'] = record_data['wPort']
        record_dict['nameTarget'] = record_data['nameTarget'].toFqdn()
    # SOA record
    if record['Type'] == 6:
        record_data = DNS_RPC_RECORD_SOA(record['Data'])
        record_dict['dwSerialNo'] = record_data['dwSerialNo']
        record_dict['dwRefresh'] = record_data['dwRefresh']
        record_dict['dwRetry'] = record_data['dwRetry']
        record_dict['dwExpire'] = record_data['dwExpire']
        record_dict['dwMinimumTtl'] = record_data['dwMinimumTtl']
        record_dict['namePrimaryServer'] = record_data['namePrimaryServer'].toFqdn()
        record_dict['zoneAdminEmail'] = record_data['zoneAdminEmail'].toFqdn()

    return record_dict
    # record_data.dump()

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
        ind = 0
        labels = ""
        for i in range(self['cchNameLength']):
            # Convert byte array of ASCII or UTF-8 data from (single?) 
            # byte character.
            labels = labels + chr(self['dnsName'][i])
        return labels

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

    def toFqdn(self):
        ind = 0
        labels = []
        for i in range(self['LabelCount']):
            nextlen = unpack('B', self['RawName'][ind:ind+1])[0]
            labels.append(self['RawName'][ind+1:ind+1+nextlen].decode('utf-8'))
            ind += nextlen + 1
        # For the final dot
        labels.append('')
        return '.'.join(labels)

    # TODO - From FQDN
    def fromFqdn(self):
        pass

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
        return socket.inet_ntoa(self['address'])

    def fromCanonical(self, canonical):
        self['address'] = socket.inet_aton(canonical)


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
    DNS_RPC_RECORD_NAME_PREFERENCE

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
        ('ipv6Address', '16s'),
    )

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
