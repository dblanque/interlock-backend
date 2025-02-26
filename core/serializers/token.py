from rest_framework import serializers as serializers
from rest_framework_simplejwt import serializers as jwt_serializers
from core.models.ldap_settings_runtime import RunningSettings
from core.models.user import User
from core.exceptions import otp as exc_otp
from core.views.mixins.logs import LogMixin
from core.views.mixins.totp import get_user_totp_device, validate_user_otp
import re

DBLogMixin = LogMixin()
class TokenObtainPairSerializer(jwt_serializers.TokenObtainPairSerializer):
	def __init__(self, *args, **kwargs):
		super().__init__(*args, **kwargs)

		self.fields['totp_code'] = serializers.CharField(required=False)
		self.fields['recovery_code'] = serializers.CharField(required=False)

	def validate(self, attrs):
		self.user: User
		data = []
		data = super().validate(attrs)
		""" self.user is set in super().validate() which also calls super().validate() """

		# TOTP
		if get_user_totp_device(user=self.user, confirmed=True):
			if 'recovery_code' in attrs:
				r_code = attrs['recovery_code']
				if r_code not in self.user.recovery_codes:
					raise exc_otp.OTPInvalidRecoveryCode
				self.user.recovery_codes.remove(r_code)
				self.user.save()
			else:
				if 'totp_code' not in attrs:
					raise exc_otp.OTPRequired
				regex = r"^[0-9]{6}$"
				if not re.match(regex, attrs['totp_code']):
					raise exc_otp.OTPInvalidData
				try:
					validate_user_otp(user=self.user, data=attrs)
				except:
					raise

		data["first_name"] = self.user.first_name or ""
		data["last_name"] = self.user.last_name or ""
		data["email"] = self.user.email or ""
		if self.user.is_superuser or self.user.username == 'admin':
			data["admin_allowed"] = True

		if RunningSettings.LDAP_LOG_LOGIN == True:
			# Log this action to DB
			DBLogMixin.log(
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
	
class OTPTokenSerializer(TokenRefreshSerializer):
	totp_code = serializers.IntegerField()
