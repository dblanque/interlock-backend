################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: interlock_backend.urls
# Interlock API URL Configuration file

# ---------------------------------- IMPORTS --------------------------------- #
#  Django
from django.contrib import admin
from django.urls import path, include

# Django-rest
from rest_framework import routers

# CORE VIEWS
from core.views.home import HomeViewSet
from core.views.token import TokenObtainPairView
from core.views.totp import TOTPViewSet
from core.views.auth import AuthViewSet
from core.views.user import UserViewSet
from core.views.ldap.user import LDAPUserViewSet
from core.views.ldap.organizational_unit import LdapDirtreeViewSet
from core.views.ldap_settings import SettingsViewSet
from core.views.logs import LogsViewSet
from core.views.ldap.group import LDAPGroupsViewSet
from core.views.test import TestViewSet
from core.views.gpo import GPOViewSet
from core.views.liveness import LivenessViewSet
from core.views.ldap.domain import LDAPDomainViewSet
from core.views.ldap.record import LDAPRecordViewSet
from core.views.debug import DebugViewSet
from core.views.application_group import ApplicationGroupViewSet
from core.views.application import ApplicationViewSet
from core.views.oidc import OidcAuthorizeView, CustomOidcViewSet
from interlock_backend.settings import DEBUG
from django.urls import re_path
################################################################################

# Initalizes Router
router = routers.DefaultRouter()
named_view_sets = {
	r"home": HomeViewSet,
	r"users": UserViewSet,
	r"ldap/users": LDAPUserViewSet,
	r"ldap/groups": LDAPGroupsViewSet,
	r"ldap/domain": LDAPDomainViewSet,
	r"ldap/record": LDAPRecordViewSet,
	r"ldap/dirtree": LdapDirtreeViewSet,
	r"settings": SettingsViewSet,
	r"logs": LogsViewSet,
	r"liveness": LivenessViewSet,
	r"totp": TOTPViewSet,
	r"application/group": ApplicationGroupViewSet,
	r"application": ApplicationViewSet,
}

if DEBUG:
	named_view_sets.update(
		{r"ldap/gpo": GPOViewSet, r"test": TestViewSet, r"debug": DebugViewSet}
	)

[
	router.register(f"api/{name}", view_set, basename=name)
	for name, view_set in named_view_sets.items()
]

urlpatterns = [
	# User Viewset Overrides
	path(
		"api/users/<int:pk>/",
		UserViewSet.as_view(
			{
				"get": UserViewSet.retrieve.__name__,
				"delete": UserViewSet.destroy.__name__,
				"post": UserViewSet.update.__name__,
				"put": UserViewSet.update.__name__,
			}
		),
		name="users-detail",
	),
	path(
		"api/users/",
		UserViewSet.as_view(
			{
				"get": UserViewSet.list.__name__,
				"post": UserViewSet.create.__name__,
			}
		),
		name="users",
	),
	# LDAP User Viewset Overrides
	path(
		"api/ldap/users/",
		LDAPUserViewSet.as_view(
			{
				"get": LDAPUserViewSet.list.__name__,
				"post": LDAPUserViewSet.create.__name__,
				"put": LDAPUserViewSet.update.__name__,
				"patch": LDAPUserViewSet.destroy.__name__,
			}
		),
		name="ldap/users",
	),
	# LDAP Group Viewset Overrides
	path(
		"api/ldap/groups/",
		LDAPGroupsViewSet.as_view(
			{
				"get": LDAPGroupsViewSet.list.__name__,
				"post": LDAPGroupsViewSet.create.__name__,
				"put": LDAPGroupsViewSet.update.__name__,
				"patch": LDAPGroupsViewSet.destroy.__name__,
			}
		),
		name="ldap/groups",
	),
	# LDAP DNS Record Viewset Overrides
	path(
		"api/ldap/record/",
		LDAPRecordViewSet.as_view(
			{
				"post": LDAPRecordViewSet.create.__name__,
				"put": LDAPRecordViewSet.update.__name__,
				"patch": LDAPRecordViewSet.destroy.__name__,
			}
		),
		name="ldap/record",
	),
	# LDAP DNS Domain Viewset Overrides
	path(
		"api/ldap/domain/",
		LDAPDomainViewSet.as_view(
			{
				"get": LDAPDomainViewSet.get_details.__name__,
				"post": LDAPDomainViewSet.create.__name__,
				"patch": LDAPDomainViewSet.destroy.__name__,
			}
		),
		name="ldap/domain",
	),
	path(
		"api/ldap/domain/zone/",
		LDAPDomainViewSet.as_view(
			{
				"get": LDAPDomainViewSet.get_zone.__name__,
				"post": LDAPDomainViewSet.get_zone.__name__,
			}
		),
		name="ldap/domain-zone",
	),
	# Organizational Unit Viewset Overrides
	path(
		"api/ldap/dirtree/",
		LdapDirtreeViewSet.as_view(
			{
				"get": LdapDirtreeViewSet.list.__name__,
				"put": LdapDirtreeViewSet.list.__name__,
				"post": LdapDirtreeViewSet.create.__name__,
				"patch": LdapDirtreeViewSet.destroy.__name__,
			}
		),
		name="ldap/dirtree",
	),
	# Settings Viewset Overrides
	path(
		"api/settings/",
		SettingsViewSet.as_view(
			{
				"get": SettingsViewSet.list.__name__,
				"post": SettingsViewSet.preset_create.__name__,
			}
		),
		name="settings",
	),
	path(
		"api/settings/<int:pk>/",
		SettingsViewSet.as_view(
			{
				"get": SettingsViewSet.retrieve.__name__,
				"delete": SettingsViewSet.preset_delete.__name__,
			}
		),
		name="settings-detail",
	),
	# Router Endpoints
	path("", include(router.urls)),
	# Admin Endpoints
	path("admin/", admin.site.urls),
	# JWT / Token Endpoints
	path("api/token/", TokenObtainPairView.as_view(), name="token-obtain"),
	path(
		"api/token/refresh/",
		AuthViewSet.as_view({"post": "refresh"}),
		name="token-refresh",
	),
	path(
		"api/token/revoke/",
		AuthViewSet.as_view({"post": "logout"}),
		name="token-revoke",
	),
	path(
		"api/auth/linux-pam/",
		AuthViewSet.as_view({"post": "linux_pam"}),
		name="auth-linux-pam",
	),
	# OIDC Endpoint overrides
	re_path(
		r"openid/authorize/?$",
		OidcAuthorizeView.as_view(),
		name="oidc-authorize",
	),
	re_path(
		r"openid/consent/?$",
		CustomOidcViewSet.as_view({"post": "consent"}),
		name="oidc-consent",
	),
	re_path(
		r"openid/reject/?$",
		CustomOidcViewSet.as_view({"post": "reject"}),
		name="oidc-reject",
	),
	# OIDC Default Endpoints
	path("openid/", include("oidc_provider.urls", namespace="oidc_provider")),
]
