from core.models.base import BaseModel
from django.utils.translation import gettext_lazy as _
from django.db import models
from core.models.types.settings import (
	BASE_SETTING_FIELDS,
	MAP_FIELD_VALUE_MODEL,
	MAP_FIELD_TYPE_MODEL,
	make_field_db_name,
	DEFAULT_FIELD_ARGS,
)
from typing import Sequence, Type, TypeVar, overload
from copy import deepcopy
from rest_framework.serializers import ValidationError

T = TypeVar(
	"T", bound="BaseSetting"
)  # Replace 'YourBaseClass' with the actual base class


def add_fields_from_dict(
	fields_dict: dict,
	validators_dict: dict = None,
	args_pass: dict = None,
	kwargs_pass: dict = None,
):
	if not validators_dict or not isinstance(kwargs_pass, dict):
		validators_dict = {}
	if not kwargs_pass or not isinstance(kwargs_pass, dict):
		kwargs_pass = {}
	if not args_pass or not isinstance(args_pass, dict):
		args_pass = {}

	def decorator(cls: Type[T]) -> Type[T]:
		field_args = []
		for setting_key, setting_fields in fields_dict.items():
			field_kwargs = deepcopy(DEFAULT_FIELD_ARGS)

			if isinstance(setting_fields, str):
				field_name = make_field_db_name(setting_key)
				field_class = MAP_FIELD_VALUE_MODEL[setting_fields]

				if setting_key in validators_dict:
					field_kwargs["validators"] = validators_dict[setting_key]
				if setting_key in kwargs_pass:
					field_kwargs = field_kwargs | kwargs_pass[setting_key]
				if setting_key in args_pass:
					field_args = args_pass[setting_key]

				cls.add_to_class(
					field_name, field_class(*field_args, **field_kwargs)
				)

			elif isinstance(setting_fields, tuple):
				for fld in setting_fields:
					field_name = make_field_db_name(fld)
					field_class = MAP_FIELD_VALUE_MODEL[fld]

					if fld in validators_dict:
						field_kwargs["validators"] = validators_dict[fld]
					if fld in kwargs_pass:
						field_kwargs = field_kwargs | kwargs_pass[fld]
					if fld in args_pass:
						field_args = args_pass[fld]

					cls.add_to_class(
						field_name, field_class(*field_args, **field_kwargs)
					)
		return cls

	return decorator


class BaseSettingsPreset(BaseModel):
	id = models.BigAutoField(verbose_name=_("id"), primary_key=True)
	name = models.CharField(
		verbose_name=_("name"),
		unique=True,
		null=False,
		blank=False,
		max_length=128,
	)
	label = models.CharField(
		verbose_name=_("label"), blank=False, null=False, max_length=64
	)
	active = models.BooleanField(
		verbose_name=_("active"), unique=True, null=True
	)

	class Meta:
		abstract = True


BASE_SETTING_TYPE_CHOICES = [(k, k.upper()) for k in BASE_SETTING_FIELDS.keys()]


class BaseSetting(BaseModel):
	setting_fields = BASE_SETTING_FIELDS
	id = models.BigAutoField(verbose_name=_("id"), primary_key=True)
	type = models.CharField(
		verbose_name=_("type"),
		choices=BASE_SETTING_TYPE_CHOICES,
		null=False,
		blank=False,
	)

	def _validate_value(self, choice_type, choice_field):
		_v = getattr(self, make_field_db_name(choice_field))
		if _v is None:
			raise ValidationError(
				f"{choice_type} cannot be null when type is {self.type}."
			)

		expected_type = MAP_FIELD_TYPE_MODEL[choice_field]
		if not isinstance(_v, expected_type):
			raise ValidationError(
				"%s must be of type %s" % (choice_field, expected_type)
			)

	@overload
	def save(
		self, force_insert=..., force_update=..., using=..., update_fields=...
	): ...

	def save(self, **kwargs):
		self.clean()
		return super().save(**kwargs)

	def clean(self):
		if not self.type or len(self.type) <= 0:
			raise ValidationError("Type is required.")
		for choice_type, choice_fields in self.setting_fields.items():
			if self.type == choice_type:
				if isinstance(choice_fields, str):
					self._validate_value(
						choice_type=choice_type,
						choice_field=choice_fields,
					)
				elif isinstance(choice_fields, Sequence):
					for cf in choice_fields:
						self._validate_value(
							choice_type=choice_type,
							choice_field=cf,
						)
		return super().clean()

	@property
	def value(self):
		value_fields = self.setting_fields[self.type]
		if isinstance(value_fields, str):
			return getattr(self, make_field_db_name(value_fields))
		elif isinstance(value_fields, tuple):
			r = []
			for vf in value_fields:
				r.append(getattr(self, make_field_db_name(vf)))
			return r
		else:
			raise TypeError("value_fields must be str or tuple.")

	def _set_value(self, v, value_fields: str | tuple) -> None:
		if isinstance(value_fields, str):
			setattr(self, make_field_db_name(value_fields), v)
		elif isinstance(value_fields, tuple):
			if isinstance(v, str):
				raise ValueError(
					"Value must be a tuple with the same length as the value fields."
				)
			for index, field in enumerate(value_fields):
				if isinstance(v, Sequence) and not isinstance(v, bytes):
					setattr(self, make_field_db_name(field), v[index])
				else:
					setattr(self, make_field_db_name(field), None)
		else:
			raise TypeError("value_fields must be str or tuple.")

	def _value_setter(self, value):
		if not self.type or len(self.type) <= 0:
			raise ValidationError(
				"Type is required for BaseSetting based models."
			)
		# Set unrelated value fields to None
		for field in self.setting_fields.values():
			self._set_value(None, value_fields=field)

		# Set corresponding value field
		self._set_value(value, value_fields=self.setting_fields[self.type])

	@value.setter
	def value(self, value):
		self._value_setter(value)

	@property
	def value_field(self):
		return self.setting_fields[self.type]

	def __str__(self):
		return f"{getattr(self, self.type, None)} - {self.value}"

	def __setattr__(self, name, value):
		if name == "value":
			self._value_setter(value)
		else:
			super().__setattr__(name, value)

	class Meta:
		abstract = True
