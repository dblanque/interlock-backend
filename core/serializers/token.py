from rest_framework import serializers as serializers
from rest_framework_simplejwt import serializers as jwt_serializers
from interlock_backend.ldap.settings_func import SettingsList
from core.models.log import logToDB
class TokenObtainPairSerializer(jwt_serializers.TokenObtainPairSerializer):

    def validate(self, attrs):
        data = []
        data = super().validate(attrs)
        """ self.user is set in super().validate() which also calls super().validate() """
        data["first_name"] = self.user.first_name or ""
        data["last_name"] = self.user.last_name or ""
        data["email"] = self.user.email or ""
        data["admin_allowed"] = self.user.is_superuser or False
        
        ldap_settings_list = SettingsList(**{"search":{
            'LDAP_LOG_LOGIN'
        }})

        if ldap_settings_list.LDAP_LOG_LOGIN == True:
            # Log this action to DB
            logToDB(
                user_id=self.user.id,
                actionType="LOGIN",
                objectClass="USER"
            )

        return data


class TokenRefreshSerializer(jwt_serializers.TokenRefreshSerializer):
    refresh = serializers.CharField()

    def validate(self, attrs):
        data = super().validate(attrs)
        
        return data