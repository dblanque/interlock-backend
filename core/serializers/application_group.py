from rest_framework import serializers
from core.models.application import ApplicationSecurityGroup


class ApplicationSecurityGroupSerializer(serializers.ModelSerializer):
	class Meta:
		model = ApplicationSecurityGroup
		fields = "__all__"
