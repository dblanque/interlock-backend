################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: core.serializers.record
# Contains the LDAP DNS Record Serializer classes

# ---------------------------------- IMPORTS --------------------------------- #
from rest_framework import serializers
from core.models.structs.ldap_dns_record import RECORD_MAPPINGS, RecordMapping
from core.models.validators.dns import (
	canonical_hostname_validator,
	domain_validator,
	srv_target_validator,
)
from core.models.validators.ldap import record_type_validator
from core.models.validators.common import ascii_validator, int32_validator
################################################################################

MAX_16_BIT = 65535
MAX_TTL_RFC_2181 = 2147483647


class DNSRecordSerializer(serializers.Serializer):
	name = serializers.CharField()
	ttl = serializers.IntegerField(max_value=MAX_TTL_RFC_2181)
	zone = serializers.CharField(validators=[domain_validator])
	serial = serializers.IntegerField(required=False)
	type = serializers.IntegerField(validators=[record_type_validator])


class DNSRecordASerializer(DNSRecordSerializer):
	address = serializers.IPAddressField(protocol="ipv4")


class DNSRecordAAAASerializer(DNSRecordSerializer):
	ipv6Address = serializers.IPAddressField(protocol="ipv6")


class DNSRecordNameNodeSerializer(DNSRecordSerializer):
	nameNode = serializers.CharField(validators=[canonical_hostname_validator])


class DNSRecordMXSerializer(DNSRecordSerializer):
	nameExchange = serializers.CharField(
		validators=[canonical_hostname_validator]
	)
	wPreference = serializers.IntegerField(max_value=MAX_16_BIT)


class DNSRecordStringDataSerializer(DNSRecordSerializer):
	stringData = serializers.CharField(
		max_length=255, validators=[ascii_validator]
	)


class DNSRecordSOASerializer(DNSRecordSerializer):
	namePrimaryServer = serializers.CharField(
		validators=[canonical_hostname_validator]
	)
	zoneAdminEmail = serializers.CharField(
		validators=[canonical_hostname_validator]
	)
	dwSerialNo = serializers.IntegerField(
		min_value=0, validators=[int32_validator]
	)
	dwRefresh = serializers.IntegerField(
		min_value=0, max_value=MAX_TTL_RFC_2181
	)
	dwRetry = serializers.IntegerField(min_value=0, max_value=MAX_TTL_RFC_2181)
	dwExpire = serializers.IntegerField(min_value=0, max_value=MAX_TTL_RFC_2181)
	dwMinimumTtl = serializers.IntegerField(
		min_value=0, max_value=MAX_TTL_RFC_2181
	)


class DNSRecordSRVSerializer(DNSRecordSerializer):
	nameTarget = serializers.CharField(validators=[srv_target_validator])
	wPriority = serializers.IntegerField(min_value=0, max_value=MAX_16_BIT)
	wWeight = serializers.IntegerField(min_value=0, max_value=MAX_16_BIT)
	wPort = serializers.IntegerField(min_value=0, max_value=MAX_16_BIT)


DNS_RECORD_SERIALIZERS: dict = {}
for record_type, record_mapping in RECORD_MAPPINGS.items():
	record_type: int
	record_mapping: RecordMapping
	_class = record_mapping["class"]
	if not _class:
		continue
	if _class == "DNS_RPC_RECORD_A":
		DNS_RECORD_SERIALIZERS[record_type] = DNSRecordASerializer
	elif _class == "DNS_RPC_RECORD_AAAA":
		DNS_RECORD_SERIALIZERS[record_type] = DNSRecordAAAASerializer
	elif _class == "DNS_RPC_RECORD_NODE_NAME":
		DNS_RECORD_SERIALIZERS[record_type] = DNSRecordNameNodeSerializer
	elif _class == "DNS_RPC_RECORD_SOA":
		DNS_RECORD_SERIALIZERS[record_type] = DNSRecordSOASerializer
	elif _class == "DNS_RPC_RECORD_STRING":
		DNS_RECORD_SERIALIZERS[record_type] = DNSRecordStringDataSerializer
	elif _class == "DNS_RPC_RECORD_NAME_PREFERENCE":
		DNS_RECORD_SERIALIZERS[record_type] = DNSRecordMXSerializer
	elif _class == "DNS_RPC_RECORD_SRV":
		DNS_RECORD_SERIALIZERS[record_type] = DNSRecordSRVSerializer
