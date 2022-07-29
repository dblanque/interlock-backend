from django.utils.translation import gettext_lazy as _
from django.db import models
from .base import BaseModel

class Log(BaseModel):
    ACTION_CHOICES = [
        ('CREATE', 'Create'),
        ('READ', 'Read'),
        ('UPDATE', 'Update'),
        ('DELETE', 'Delete'),
        ('LOGIN', 'Login'),
        ('LOGOUT', 'Logout'),
        ('OPEN', 'Open'),
        ('CLOSE', 'Close'),
    ]

    CLASS_CHOICES = [
        ('USER', 'User'),
        ('GROUP', 'Group'),
        ('OU', 'Organizational Unit'),
        ('DOM', 'Domain'),
        ('GPO', 'Group Policy Object'),
        ('LDAP', 'LDAP Object'),
        ('CONN', 'Connection'),
    ]

    id = models.BigAutoField(primary_key=True)
    user = models.ForeignKey('User', on_delete=models.CASCADE)
    actionType = models.CharField(_("actionType"), choices=ACTION_CHOICES, max_length=256, null=False, blank=False)
    objectClass = models.CharField(_("objectClass"), choices=CLASS_CHOICES, max_length=256, null=False, blank=False)
    affectedObject = models.CharField(_("affectedObject"), max_length=256, null=True, blank=True)
    extraMessage = models.CharField(_("extraMessage"), max_length=256, null=True, blank=True)
