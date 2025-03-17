from rest_framework import serializers
from django.core.validators import RegexValidator
from core.models.application import Application


class ApplicationSerializer(serializers.ModelSerializer):
	name = serializers.CharField(validators=[RegexValidator("^[\sA-Za-z0-9_-]*$")])

	class Meta:
		model = Application
		fields = "__all__"
		extra_kwargs = {"client_secret": {"write_only": True}}
