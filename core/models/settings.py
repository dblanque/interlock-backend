from django.contrib.auth.models import PermissionsMixin
from django.utils.translation import gettext_lazy as _
from django.db import models
from .base import BaseModel
from interlock_backend.ldap_settings import SETTINGS_WITH_ALLOWABLE_OVERRIDE

class Setting(BaseModel):
    use_in_migrations = True
    TYPE_INTEGER = 'INT'
    TYPE_FLOAT = 'FLO'
    TYPE_STRING = 'STR'
    TYPE_LIST = 'LI'
    TYPE_BOOLEAN = 'BOOL'
    TYPE_OBJECT = 'OBJ'
    TYPE_TUPLE = 'TUP'

    TYPE_CHOICES = [
        (TYPE_INTEGER, 'integer'),
        (TYPE_FLOAT, 'float'),
        (TYPE_STRING, 'string'),
        (TYPE_LIST, 'list'),
        (TYPE_BOOLEAN, 'boolean'),
        (TYPE_OBJECT, 'object'),
        (TYPE_TUPLE, 'tuple'),
    ]

    id = models.CharField(primary_key=True, unique=True, max_length=64)
    value = models.CharField(_("value"), max_length=256)
    type = models.CharField(choices=TYPE_CHOICES, max_length=256)