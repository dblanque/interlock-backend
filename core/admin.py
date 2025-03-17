################################## IMPORTS #####################################
# Django
from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as DjangoUserAdmin
from django.utils.translation import gettext_lazy as _
from django.contrib.auth.forms import (
	UserChangeForm,
	UserCreationForm as DjangoUserCreationForm,
	AdminPasswordChangeForm,
)
from django import forms
from django.contrib.postgres.forms import SimpleArrayField

# Core
from core import models
################################################################################


class UserCreationForm(DjangoUserCreationForm):
	class Meta:
		fields = ("username",)
		field_classes = {"username": forms.CharField}


@admin.register(models.User)
class UserAdmin(DjangoUserAdmin):
	add_form_template = "admin/auth/user/add_form.html"
	change_user_password_template = None
	fieldsets = (
		(
			_("Personal info"),
			{"fields": ("username", "first_name", "last_name", "email", "password")},
		),
		(
			_("Permissions"),
			{
				"fields": (
					"is_staff",
					"is_superuser",
					"deleted",
				)
			},
		),
		(
			_("Dates"),
			{
				"fields": (
					"last_login",
					"created_at",
					"modified_at",
					"deleted_at",
				)
			},
		),
	)
	add_fieldsets = (
		(
			None,
			{
				"classes": ("wide",),
				"fields": ("email", "password1", "password2"),
			},
		),
	)
	form = UserChangeForm
	add_form = UserCreationForm
	change_password_form = AdminPasswordChangeForm
	list_display = ("username", "email", "is_staff", "is_superuser")
	list_filter = ("is_staff", "is_superuser", "deleted", "groups")
	readonly_fields = ("created_at", "modified_at", "deleted_at", "deleted")
	search_fields = ("email",)
	ordering = ("-created_at",)


class ASGForm(forms.ModelForm):
	ldap_objects = SimpleArrayField(forms.CharField(), delimiter="|")


@admin.register(models.ApplicationSecurityGroup)
class ASGAdmin(admin.ModelAdmin):
	form = ASGForm
	list_display = (
		"get_application_name",
		"enabled",
	)

	def get_application_name(self, obj: models.ApplicationSecurityGroup):
		return obj.application.name


@admin.register(models.Application)
class ApplicationAdmin(admin.ModelAdmin):
	list_display = (
		"name",
		"enabled",
		"client_id",
		"client_secret",
		"redirect_uris",
		"scopes",
	)
