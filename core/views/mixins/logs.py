from rest_framework import viewsets
from core.config.runtime import RuntimeSettings
from core.models.log import Log


class LogMixin(viewsets.ViewSetMixin):
	def log(self, **kwargs):
		# This function rotates logs based on a Maximum Limit Setting
		log_limit = RuntimeSettings.LDAP_LOG_MAX

		# Truncate Logs if necessary
		if Log.objects.count() > log_limit:
			Log.objects.filter(id__gt=log_limit).delete()

		unrotated_log_count = Log.objects.filter(rotated=False).count()
		last_unrotated_log = Log.objects.filter(rotated=False).last()
		# If there's no last unrotated log, set to 0 to avoid conditional issues
		if last_unrotated_log is None:
			last_unrotated_id = 0
		else:
			last_unrotated_id = last_unrotated_log.id

		# If there are no unrotated logs or the range is exceeded, restart sequence
		if unrotated_log_count < 1 or last_unrotated_id >= log_limit:
			Log.objects.all().update(rotated=True)
			log_id = 1
		else:
			log_id = Log.objects.filter(rotated=False).last().id + 1

		log_with_overlapping_id = Log.objects.filter(id=log_id)
		if log_with_overlapping_id.exists():
			log_with_overlapping_id.delete()

		log_instance = Log(id=log_id, rotated=False, **kwargs)
		log_instance.save()

		return log_instance.id
