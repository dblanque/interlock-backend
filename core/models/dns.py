from core.utils.dns import *
from core.utils import dnstool
from interlock_backend.ldap.settings_func import SettingsList
import ipaddress

class ldapDNS():
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
            print('Found %d domain DNS zones:' % len(zones))
            for zone in zones:
                print('    %s' % zone)
        return zones

    def list_dns_zones(self):
        zones = dnstool.get_dns_zones(self.connection, self.forestroot)
        if len(zones) > 0:
            print('Found %d forest DNS zones:' % len(zones))
            for zone in zones:
                print('    %s' % zone)
        return zones
