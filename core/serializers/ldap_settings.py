from rest_framework import serializers
from django.core.validators import RegexValidator
from core.models.ldap_settings import LDAPSetting, LDAPPreset

class LDAPPresetSerializer(serializers.ModelSerializer):
    name = serializers.CharField(validators=[RegexValidator("^[A-Za-z0-9_-]*$")])
    class Meta:
        model = LDAPPreset
        fields = "__all__"

class LDAPSettingSerializer(serializers.ModelSerializer):
    name = serializers.CharField(validators=[])
    preset = LDAPPresetSerializer(source="ldap_preset", read_only=True)
    class Meta:
        model = LDAPSetting
        fields = "__all__"
