################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: core.models.log
# Contains the Model for Log Entries
#
#---------------------------------- IMPORTS -----------------------------------#
### Django
from django.utils.translation import gettext_lazy as _
from django.db.models.manager import BaseManager as Manager
from django.db import models
from django.utils import timezone as tz

### Base
from .base import BaseManager

### Choices
from .choices.log import ACTION_CHOICES, CLASS_CHOICES
# ---------------------------------------------------------------------------- #
class BaseLogModel(models.Model):

    logged_at = models.DateTimeField(_("logged at"), auto_now_add=True)
    rotated = models.BooleanField(_("rotated"), default=False)

    notes = models.TextField(blank=True, null=True)
    objects = BaseManager()
    all_objects = Manager()

    def rotate(self, using=None, keep_parents=False):
        self.rotated_at = tz.now()
        self.rotated = True
        self.save(update_fields=["rotated_at", "rotated"])

    def delete(self, using=None, keep_parents=False):
        """
        Normally use delete instead of this.
        :param using:
        :param keep_parents:
        :return:
        """
        return super().delete(using=using, keep_parents=keep_parents)

    def __str__(self):
        if hasattr(self, 'name'):
            return self.name
        return super(BaseLogModel, self).__str__()

    class Meta:
        abstract = True
class Log(BaseLogModel):

    id = models.BigIntegerField(primary_key=True)
    user = models.ForeignKey('User', on_delete=models.CASCADE)
    actionType = models.CharField(_("actionType"), choices=ACTION_CHOICES, max_length=256, null=False, blank=False)
    objectClass = models.CharField(_("objectClass"), choices=CLASS_CHOICES, max_length=256, null=False, blank=False)
    affectedObject = models.JSONField(_("affectedObject"), null=True, blank=True)
    extraMessage = models.CharField(_("extraMessage"), max_length=256, null=True, blank=True)
