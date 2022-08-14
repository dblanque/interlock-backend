# TODO - Implement this serializer
from rest_framework import serializers

class RecordSerializer_A(serializers.Serializer):
    recordName = serializers.CharField(required=True)
    address = serializers.IPAddressField(required=True)

class RecordSerializer_NODENAME(serializers.Serializer):
    recordName = serializers.CharField(required=True)
    nameNode = serializers.CharField(required=True)

