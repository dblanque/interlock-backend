from rest_framework import viewsets
from core.models.ldap_settings_db import *
from core.models.log import Log
class LogMixin(viewsets.ViewSetMixin):
	def log(**kwargs):
		# This function rotates logs based on a Maximum Limit Setting
		logLimit = LDAP_LOG_MAX

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
