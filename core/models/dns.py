from core.utils.dns import *
from core.utils import dnstool
from interlock_backend.ldap.settings_func import SettingsList
import ipaddress
import logging

logger = logging.getLogger(__name__)

def record_to_dict(record, ts=False):
    # For original reference see print_record in dnstool.py
    try:
        rtype = dnstool.RECORD_TYPE_MAPPING[record['Type']]
    except KeyError:
        rtype = 'Unsupported'

    record_dict = dict()

    # Check if record is Tombstoned / Inactive
    if ts:
        record_dict['ts'] = True
    else:
        record_dict['ts'] = False

    record_dict['type'] = record['Type']
    record_dict['typeName'] = rtype
    record_dict['serial'] = record['Serial']
    if record['Type'] == 0:
        tstime = dnstool.DNS_RPC_RECORD_TS(record['Data'])
        record_dict['tstime'] = tstime.toDatetime()
    # A record
    if record['Type'] == 1:
        address = dnstool.DNS_RPC_RECORD_A(record['Data'])
        record_dict['address'] = address.formatCanonical()
    # NS record or CNAME record
    if record['Type'] == 2 or record['Type'] == 5:
        address = dnstool.DNS_RPC_RECORD_NODE_NAME(record['Data'])
        record_dict['address'] = address['nameNode'].toFqdn()
    # SRV record
    if record['Type'] == 33:
        record_data = dnstool.DNS_RPC_RECORD_SRV(record['Data'])
        record_dict['wPriority'] = record_data['wPriority']
        record_dict['wWeight'] = record_data['wWeight']
        record_dict['wPort'] = record_data['wPort']
        record_dict['nameTarget'] = record_data['nameTarget'].toFqdn()
    # SOA record
    if record['Type'] == 6:
        record_data = dnstool.DNS_RPC_RECORD_SOA(record['Data'])
        record_dict['dwSerialNo'] = record_data['dwSerialNo']
        record_dict['dwRefresh'] = record_data['dwRefresh']
        record_dict['dwRetry'] = record_data['dwRetry']
        record_dict['dwExpire'] = record_data['dwExpire']
        record_dict['dwMinimumTtl'] = record_data['dwMinimumTtl']
        record_dict['namePrimaryServer'] = record_data['namePrimaryServer'].toFqdn()
        record_dict['zoneAdminEmail'] = record_data['zoneAdminEmail'].toFqdn()

    return record_dict
    # record_data.dump()

class LDAPDNS():
    def __init__(self, connection, legacy=False):
        ######################## Get Latest Settings ###########################
        ldap_settings_list = SettingsList(**{"search":{
            'LDAP_AUTH_SEARCH_BASE'
        }})

        if legacy == True:
            self.dnsroot = 'CN=MicrosoftDNS,CN=System,%s' % ldap_settings_list.LDAP_AUTH_SEARCH_BASE
        else:
            self.dnsroot = 'CN=MicrosoftDNS,DC=DomainDnsZones,%s' % ldap_settings_list.LDAP_AUTH_SEARCH_BASE
        
        self.forestroot = 'CN=MicrosoftDNS,DC=ForestDnsZones,%s' % ldap_settings_list.LDAP_AUTH_SEARCH_BASE  
        self.connection = connection

    def list_dns_zones(self):
        zones = dnstool.get_dns_zones(self.connection, self.dnsroot)
        if len(zones) > 0:
            logger.info('Found %d domain DNS zone(s):' % len(zones))
            for zone in zones:
                logger.info('    %s' % zone)
        return zones

    def list_forest_zones(self):
        zones = dnstool.get_dns_zones(self.connection, self.forestroot)
        if len(zones) > 0:
            logger.info('Found %d forest DNS zone(s):' % len(zones))
            for zone in zones:
                logger.info('    %s' % zone)
        return zones
