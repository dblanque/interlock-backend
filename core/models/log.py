################################## IMPORTS #####################################
### Django
from django.utils.translation import gettext_lazy as _
from django.db.models.manager import BaseManager as Manager
from django.db import models
from django.utils import timezone as tz

### Base
from .base import BaseManager

### Choices
from .choices.log import ACTION_CHOICES, CLASS_CHOICES

### Interlock
from interlock_backend.ldap.settings_func import SettingsList
################################################################################
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

def logToDB(**kwargs):
    # This function rotates logs based on a Maximum Limit Setting
    ldap_settings_list = SettingsList(**{"search":{ 'LDAP_LOG_MAX' }})
    logLimit = ldap_settings_list.LDAP_LOG_MAX

    # Truncate Logs if necessary
    if Log.objects.count() > logLimit:
        Log.objects.filter(id__gt=logLimit).delete()

    unrotatedLogCount = Log.objects.filter(rotated=False).count()
    lastUnrotatedLog = Log.objects.filter(rotated=False).last()
    # If there's no last unrotated log, set to 0 to avoid conditional issues
    if lastUnrotatedLog is None:
        lastUnrotatedLogId = 0
    else:
        lastUnrotatedLogId = lastUnrotatedLog.id

    # If there are no unrotated logs or the range is exceeded, restart sequence
    if unrotatedLogCount < 1 or lastUnrotatedLogId >= logLimit:
        Log.objects.all().update(rotated=True)
        logId = 1
    else:
        logId = Log.objects.filter(rotated=False).last().id + 1

    logWithCurrentId = Log.objects.filter(id=logId)
    if logWithCurrentId.count() > 0:
        logWithCurrentId.delete()
        logAction = Log(id=logId, rotated=False, **kwargs)
        logAction.save()
    else:
        logAction = Log(id=logId, rotated=False, **kwargs)
        logAction.save()

    return logAction.id
