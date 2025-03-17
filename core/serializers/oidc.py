from rest_framework import serializers
from oidc_provider.models import Client


class ClientSerializer(serializers.ModelSerializer):
	class Meta:
		model = Client
		fields = "__all__"
