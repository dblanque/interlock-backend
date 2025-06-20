################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: core.serializers.token
# Contains token/auth serializer classes and utilities

# ---------------------------------- IMPORTS -----------------------------------#
from rest_framework import serializers as serializers
from rest_framework_simplejwt import serializers as jwt_serializers
from rest_framework_simplejwt.tokens import RefreshToken
from core.models.choices.log import LOG_CLASS_USER, LOG_ACTION_LOGIN
from core.models.user import User
from core.exceptions import otp as exc_otp
from core.views.mixins.logs import LogMixin
from rest_framework.exceptions import AuthenticationFailed
from core.views.mixins.totp import validate_user_otp
from interlock_backend.settings import DEFAULT_SUPERUSER_USERNAME
from django_otp import user_has_device
import re

################################################################################
DBLogMixin = LogMixin()


def user_is_not_authenticated(user: User) -> bool:
	"""Check if user is authenticated, enabled, and not anonymous"""
	if user.is_anonymous or not user.is_enabled:
		return True
	return False


class TokenObtainPairSerializer(jwt_serializers.TokenObtainPairSerializer):
	def __init__(self, *args, **kwargs):
		super().__init__(*args, **kwargs)

		self.fields["totp_code"] = serializers.CharField(required=False)
		self.fields["recovery_code"] = serializers.CharField(required=False)

	def validate(self, attrs):
		# self.user is set in TokenObtainSerializer.validate()
		self.user: User
		data = jwt_serializers.TokenObtainSerializer.validate(self, attrs)
		self.refresh: RefreshToken = self.get_token(self.user)
		data["refresh"] = str(self.refresh)
		data["access"] = str(self.refresh.access_token)

		if user_is_not_authenticated(self.user):
			raise AuthenticationFailed

		# TOTP
		if user_has_device(self.user, confirmed=True):
			if "recovery_code" in attrs:
				r_code = attrs["recovery_code"]
				if r_code not in self.user.recovery_codes:
					raise exc_otp.OTPInvalidRecoveryCode
				self.user.recovery_codes.remove(r_code)
				self.user.save()
			else:
				if "totp_code" not in attrs:
					raise exc_otp.OTPRequired
				regex = r"^[0-9]{6}$"
				if not re.match(regex, attrs["totp_code"]):
					raise exc_otp.OTPInvalidData
				validate_user_otp(user=self.user, data=attrs)

		data["first_name"] = self.user.first_name or ""
		data["last_name"] = self.user.last_name or ""
		data["email"] = self.user.email or ""
		data["user_type"] = self.user.user_type or ""
		if (
			self.user.is_superuser
			or self.user.username == DEFAULT_SUPERUSER_USERNAME
		):
			data["admin_allowed"] = True

		DBLogMixin.log(
			user=self.user.id,
			operation_type=LOG_ACTION_LOGIN,
			log_target_class=LOG_CLASS_USER,
		)
		return data


class TokenRefreshSerializer(jwt_serializers.TokenRefreshSerializer):
	refresh = serializers.CharField()

	def validate(self, attrs):
		self.user: User
		data = super().validate(attrs)
		if user_is_not_authenticated(self.user):
			raise AuthenticationFailed
		return data


class OTPTokenSerializer(TokenRefreshSerializer):
	totp_code = serializers.IntegerField()
