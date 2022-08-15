from importlib import import_module
from core.utils.dns import *
from core.utils import dnstool
from interlock_backend.ldap.settings_func import SettingsList
from core.exceptions import dns as exc_dns
from interlock_backend.ldap.adsi import addSearchFilter
from core.utils.dnstool import (
    new_record,
    record_to_dict,
    get_next_serial
)
from ldap3 import (
    MODIFY_ADD,
    MODIFY_DELETE,
    MODIFY_INCREMENT,
    MODIFY_REPLACE
)
from core.models.dnsRecordClasses import *
from interlock_backend.ldap.connector import LDAPInfo
import ipaddress
import logging

logger = logging.getLogger(__name__)
class LDAPDNS():
    def __init__(self, connection, legacy=False):
        ######################## Get Latest Settings ###########################
        self.ldap_settings_list = SettingsList(**{"search":{
            'LDAP_AUTH_SEARCH_BASE',
            'LDAP_DOMAIN'
        }})

        if legacy == True:
            self.dnsroot = 'CN=MicrosoftDNS,CN=System,%s' % self.ldap_settings_list.LDAP_AUTH_SEARCH_BASE
        else:
            self.dnsroot = 'CN=MicrosoftDNS,DC=DomainDnsZones,%s' % self.ldap_settings_list.LDAP_AUTH_SEARCH_BASE
        
        self.forestroot = 'CN=MicrosoftDNS,DC=ForestDnsZones,%s' % self.ldap_settings_list.LDAP_AUTH_SEARCH_BASE  
        self.connection = connection
        self.list_dns_zones()
        self.list_forest_zones()

    def list_dns_zones(self):
        zones = dnstool.get_dns_zones(self.connection, self.dnsroot)
        self.dnszones = zones
        if len(zones) > 0:
            logger.debug('Found %d domain DNS zone(s):' % len(zones))
            for zone in zones:
                logger.debug('    %s' % zone)

    def list_forest_zones(self):
        zones = dnstool.get_dns_zones(self.connection, self.forestroot)
        self.forestzones = zones
        if len(zones) > 0:
            logger.debug('Found %d forest DNS zone(s):' % len(zones))
            for zone in zones:
                logger.debug('    %s' % zone)

class LDAPRecord(LDAPDNS):

    def __init__(
        self, 
        connection, 
        legacy=False,
        rName=None,
        rZone=None,
        rType=None,
        zoneType="fwdLookup",
    ):
        super().__init__(connection=connection, legacy=legacy)

        self.ldap_info = LDAPInfo()
        self.schemaNamingContext = self.ldap_info.get_schema_naming_context()
        if rName is None:
            raise ValueError("Name cannot be none (LDAPRecord Object Class)")
        if rZone is None:
            raise ValueError("Zone cannot be none (LDAPRecord Object Class)")
        if rType is None:
            raise ValueError("Record Type cannot be none (LDAPRecord Object Class)")
        if zoneType != 'fwdLookup':
            raise ValueError("Reverse Lookup Entries are unsupported (LDAPRecord Object Class)")

        self.rawEntry = None
        self.data = None
        self.name = rName
        self.zone = rZone
        self.zoneType = zoneType
        self.type = rType
        self.distinguishedName = "DC=%s,DC=%s,%s" % (self.name, self.zone, self.dnsroot)
        self.fetch()

    def fetch(self):
        if self.zone not in self.dnszones:
            msg = "Target zone (%s) is not in the LDAP Server DNS List" % (self.zone)
            print(self.dnszones)
            raise Exception(msg)

        if self.name.endswith(self.zone) or self.zone in self.name:
            raise exc_dns.DNSZoneInRecord

        searchFilter = addSearchFilter("", "objectClass=dnsNode")
        searchFilter = addSearchFilter(searchFilter, "distinguishedName=" + self.distinguishedName)
        attributes=['dnsRecord','dNSTombstoned','name']

        search_target = 'DC=%s,%s' % (self.zone, self.dnsroot)
        self.connection.search(
            search_base=search_target,
            search_filter=searchFilter,
            attributes=attributes
        )
        if len(self.connection.response) > 0:
            self.rawEntry = self.connection.response[0]
        else: 
            return None

        excludeEntries = [
            'ForestDnsZones',
            'DomainDnsZones'
        ]

        result = list()
        record_dict = dict()

        if self.rawEntry['type'] == 'searchResEntry':
            if self.rawEntry['dn'] == self.distinguishedName:
                logger.debug("Entry exists")

            # Set Record Name
            record_name = self.rawEntry['raw_attributes']['name'][0]
            record_name = str(record_name)[2:-1]
            logger.debug(record_name)

            # Set Record Data
            for record in self.rawEntry['raw_attributes']['dnsRecord']:
                dr = dnstool.DNS_RECORD(record)
                logger.debug(dr)
                record_dict = record_to_dict(dr, self.rawEntry['attributes']['dNSTombstoned'])
                record_dict['name'] = record_name
                logger.debug('Record: %s, Starts With Underscore: %s, Exclude Entry: %s' % (record_name, record_name.startswith("_"), record_name in excludeEntries))
                if (not record_name.startswith("_") 
                    and record_name not in excludeEntries):
                    result.append(record_dict)

            if len(result) > 0:
                self.data = result
        return self.data

    def __attributes__(self):
        # Exclude specific keys from self record attributes
        excludedKeys = [
            'rawEntry',
            'connection',
            'ldap_info',
            'ldap_settings_list'
        ]
        return [v for v in self.__dict__.keys() if v not in excludedKeys]

    def __printAttributes__(self, printRawData=False):
        if printRawData == True:
            msg = "%s: %s" % ('rawEntry', self.rawEntry)
            print(msg)
        for attr in self.__attributes__():
            msg = "%s: %s" % (attr, str(getattr(self, attr)))
            print(msg)

    def __connection__(self):
        return self.connection

    def makeRecord(self, values, serial=None, ttl=180):
        if serial is None:
            serial = get_next_serial(self.connection.server.host, self.zone, tcp=False)

        ## Check if class type is supported for creation ##
        if (self.type in RECORD_MAPPINGS):
            record = new_record(self.type, get_next_serial(self.connection.server.host, self.zone, tcp=False), ttl=ttl)
            # Dynamically fetch the class based on the mapping
            if RECORD_MAPPINGS[self.type]['class'] != None:
                if RECORD_MAPPINGS[self.type]['class'] == "DNS_RPC_RECORD_NODE_NAME":
                    # If it's NODE_NAME then re-create the record Data with a sub-class DNS_COUNT_NAME
                    record['Data'] = DNS_COUNT_NAME()
                elif RECORD_MAPPINGS[self.type]['class'] == "DNS_RPC_RECORD_NAME_PREFERENCE":
                    # If it's NODE_NAME then re-create the record Data with a sub-class DNS_COUNT_NAME
                    record['Data'] = DNS_COUNT_NAME()
                elif RECORD_MAPPINGS[self.type]['class'] == "DNS_RPC_RECORD_STRING":
                    # If it's RECORD_STRING then re-create the record Data with a sub-class DNS_RPC_NAME
                    record['Data'] = DNS_RPC_NAME()
                else:
                    # Standard Class Creation
                    record['Data'] = getattr(dnstool, RECORD_MAPPINGS[self.type]['class'])()

                # ! Print Chosen Class    
                # print(RECORD_MAPPINGS[self.type]['class'])

                numFields = [
                    'dwSerialNo',
                    'dwRefresh',
                    'dwRetry',
                    'dwExpire',
                    'dwMinimumTtl',
                    'wPriority',
                    'wWeight',
                    'wPort',
                ]

                # Additional Operations based on special case type
                for field in RECORD_MAPPINGS[self.type]['fields']:
                    if RECORD_MAPPINGS[self.type]['class'] == "DNS_RPC_RECORD_A":
                        record['Data'].fromCanonical(values[field])

                    if RECORD_MAPPINGS[self.type]['class'] == "DNS_RPC_RECORD_NODE_NAME":
                        record['Data'].toCountName(values[field])

                    if RECORD_MAPPINGS[self.type]['class'] == "DNS_RPC_RECORD_STRING":
                        if field == 'stringData':
                            record['Data'].toRPCName(values[field])

                    if RECORD_MAPPINGS[self.type]['class'] == "DNS_RPC_RECORD_NAME_PREFERENCE":
                        if field == 'wPreference':
                            record['Data'].insert_field_to_struct(fieldName=field, fieldStructVal='>H')
                            record['Data'].setField(field, value=values[field])
                        if field == 'nameExchange':
                            record['Data'].toCountName(values[field])
            
                    if RECORD_MAPPINGS[self.type]['class'] == "DNS_RPC_RECORD_SOA":
                        if field in numFields:
                            record['Data'].setField(field, values[field])
                        else:
                            record['Data'][field] = record['Data'].addCountName(values[field])

                    if RECORD_MAPPINGS[self.type]['class'] == "DNS_RPC_RECORD_SRV":
                        if field in numFields:
                            record['Data'].setField(field, values[field])
                        else:
                            record['Data'][field] = record['Data'].addCountName(values[field])
            return record
        else:
            exception = exc_dns.DNSRecordTypeUnsupported
            data = {
                "code": exception.default_code,
                "typeName": RECORD_MAPPINGS[self.type]['name'],
                "typeCode": self.type,
                "name": self.name,
            }
            exception.setDetail(exception, data)
            self.connection.unbind()
            raise exception
   
    def create(self, values):
        if 'ttl' not in values:
            values['ttl'] = 900
        self.structure = self.makeRecord(values, ttl=values['ttl'])

        # ! For debugging, do the decoding process to see if it's not a broken entry
        result = self.structure.getData()
        dr = dnstool.DNS_RECORD(result)

        ## Check if LDAP Entry Exists ##
        # LDAP Entry does not exist
        if self.rawEntry is None:
            logger.info("Create Entry for %s" % (self.name))
            logger.info(record_to_dict(dr, ts=False))
            node_data = {
                'objectCategory': 'CN=Dns-Node,%s' % self.schemaNamingContext,
                'dNSTombstoned': False,
                'name': self.name,
                'dnsRecord': [ self.structure.getData() ]
            }
            self.connection.add(self.distinguishedName, ['top', 'dnsNode'], node_data)
        # LDAP entry exists
        else:
            if 'mainField' in RECORD_MAPPINGS[self.type]:
                mainField = RECORD_MAPPINGS[self.type]['mainField']
            else:
                mainField = RECORD_MAPPINGS[self.type]['fields'][0]

            # Check if record exists in Entry
            exists = self.checkRecordExists(mainField=mainField, mainFieldValue=values[mainField])
            if isinstance(exists, int) and exists != False:
                print("%s Record already exists in an LDAP Entry (Conflicting value: %s)" % (RECORD_MAPPINGS[self.type]['name'], values[mainField]))
                self.connection.unbind()
                raise exc_dns.DNSRecordTypeConflict

            # Check for record type conflicts in Entry
            try:
                self.checkRecordTypeCollision()
            except Exception as e:
                print(e)
                self.connection.unbind()
                raise exc_dns.DNSRecordTypeConflict
            logger.info("Adding Record to Entry with name %s" % (self.name))
            logger.info(record_to_dict(dr, ts=False))
            
            # If all checks passed
            self.connection.modify(self.distinguishedName, {'dnsRecord': [( MODIFY_ADD, self.structure.getData() )]})
        return self.connection.result

    def update(self, recordIndex, values, oldValues):
        self.structure = self.makeRecord(values, ttl=values['ttl'], serial=values['serial'])
        structureAsData = self.structure.getData()
        return None

    def delete(self, recordIndex, values):
        self.structure = self.makeRecord(values, ttl=values['ttl'], serial=values['serial'])
        structureAsData = self.structure.getData()

        # Check if entry has more than one record
        # More than one record -> delete by record index
        if len(self.data) >= 2:
            if self.rawEntry['raw_attributes']['dnsRecord'][recordIndex] == structureAsData:
                self.connection.modify(self.distinguishedName, {'dnsRecord': [( MODIFY_DELETE, structureAsData )]})
            else:
                raise exc_dns.DNSRecordTypeConflict
        else:
            self.connection.delete(self.distinguishedName)
        # Only record -> delete entire entry
        return self.connection.result

    def checkRecordExists(self, mainField, mainFieldValue):
        if self.data is not None:
            if len(self.data) > 0:
                for index, record in enumerate(self.data):
                    if (record['name'] == self.name
                    and record['type'] == self.type
                    and record[mainField] == mainFieldValue):
                        return index
        return False

    def checkRecordTypeCollision(self):
        if self.data is not None:
            if len(self.data) > 0:
                exc = False
                msg = None
                for record in self.data:
                    if (
                        # If Any other type of Entry conflicts with CNAME
                        (self.type == DNS_RECORD_TYPE_CNAME and record['type'] != DNS_RECORD_TYPE_CNAME)
                        # A -> CNAME
                        or
                        (self.type == DNS_RECORD_TYPE_A and record['type'] == DNS_RECORD_TYPE_CNAME)
                        # A -> AAAA
                        or
                        (self.type == DNS_RECORD_TYPE_A and record['type'] == DNS_RECORD_TYPE_AAAA)
                        # AAAA -> CNAME
                        or
                        (self.type == DNS_RECORD_TYPE_AAAA and record['type'] == DNS_RECORD_TYPE_CNAME)
                        # AAAA -> A
                        or
                        (self.type == DNS_RECORD_TYPE_AAAA and record['type'] == DNS_RECORD_TYPE_A)
                        ):
                        exc = True
                        msg = "A conflicting DNS Record %s was found for this %s Entry: \n -> %s" % \
                        (RECORD_MAPPINGS[record['type']]['name'], RECORD_MAPPINGS[self.type]['name'], record)
                if exc == True:
                    raise Exception(msg)
        return False
