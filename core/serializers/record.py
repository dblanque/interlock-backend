from rest_framework import serializers


class DNSRecordSerializer(serializers.Serializer):
	name = serializers.CharField()
	ttl = serializers.IntegerField()
	zone = serializers.CharField()
	serial = serializers.IntegerField(required=False)
	type = serializers.IntegerField()
	address = serializers.IPAddressField(required=False, protocol="ipv4")
	ipv6Address = serializers.IPAddressField(required=False, protocol="ipv6")
	nameExchange = serializers.CharField(required=False)
	nameTarget = serializers.CharField(required=False)
	wPreference = serializers.IntegerField(required=False)
	wPriority = serializers.IntegerField(required=False)
	wWeight = serializers.IntegerField(required=False)
	wPort = serializers.IntegerField(required=False)
	dwSerialNo = serializers.IntegerField(required=False)
	dwRefresh = serializers.IntegerField(required=False)
	dwRetry = serializers.IntegerField(required=False)
	dwExpire = serializers.IntegerField(required=False)
	dwMinimumTtl = serializers.IntegerField(required=False)
	namePrimaryServer = serializers.CharField(required=False)
	zoneAdminEmail = serializers.CharField(required=False)


class DNSRecordASerializer(DNSRecordSerializer):
	address = serializers.IPAddressField(protocol="ipv4")


class DNSRecordAAAASerializer(DNSRecordSerializer):
	ipv6Address = serializers.IPAddressField(protocol="ipv6")


class DNSRecordCNAMESerializer(DNSRecordSerializer):
	nameNode = serializers.CharField()


class DNSRecordNSSerializer(DNSRecordCNAMESerializer):
	pass


class DNSRecordMXSerializer(DNSRecordSerializer):
	nameExchange = serializers.CharField()
	wPreference = serializers.IntegerField()


class DNSRecordTXTSerializer(DNSRecordSerializer):
	stringData = serializers.CharField()


class DNSRecordSOASerializer(DNSRecordSerializer):
	namePrimaryServer = serializers.CharField()
	zoneAdminEmail = serializers.CharField()
	dwSerialNo = serializers.IntegerField()
	dwRefresh = serializers.IntegerField()
	dwRetry = serializers.IntegerField()
	dwExpire = serializers.IntegerField()
	dwMinimumTtl = serializers.IntegerField()


class DNSRecordSRVSerializer(DNSRecordSerializer):
	nameTarget = serializers.CharField()
	wPriority = serializers.IntegerField()
	wWeight = serializers.IntegerField()
	wPort = serializers.IntegerField()
