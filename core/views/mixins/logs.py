################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: core.views.mixins.logs
# Contains the Mixin for Log related operations

# ---------------------------------- IMPORTS --------------------------------- #
from rest_framework import viewsets
from core.config.runtime import RuntimeSettings
from core.models.user import User
from core.models.log import Log
from django.db import transaction
from django.db.models import Count, Max
import logging

#################################################################################
logger = logging.getLogger()


class LogMixin(viewsets.ViewSetMixin):
	def log(
		self,
		user: int | User,
		operation_type,
		log_target_class,
		log_target=None,
		message=None,
		**kwargs,
	):
		"""Maintains log rotation while ensuring atomic operations."""
		if not any(
			isinstance(user, t)
			for t in (
				int,
				User,
			)
		):
			raise TypeError("user must be of type int | User")

		LOG_OPTION = f"LDAP_LOG_{operation_type}"
		if not hasattr(RuntimeSettings, LOG_OPTION):
			logger.warning(
				"RuntimeSettings does not have the %s attribute.", LOG_OPTION
			)
		if not getattr(RuntimeSettings, LOG_OPTION, False):
			return None
		log_limit = RuntimeSettings.LDAP_LOG_MAX

		if isinstance(user, int):
			kwargs["user_id"] = user
		else:
			kwargs["user"] = user

		with transaction.atomic():
			# Get aggregated log information in a single query
			log_info = Log.objects.aggregate(
				total_logs=Count("id"), max_id=Max("id")
			)

			# Rotate logs if necessary using bulk operations
			if log_info["total_logs"] >= log_limit:
				self._rotate_logs(log_limit, log_info["total_logs"])

			# Determine next log ID using database-generated sequence
			log_instance = Log(
				operation_type=operation_type,
				log_target_class=log_target_class,
				log_target=log_target,
				message=message,
				**kwargs,
			)
			log_instance.save(force_insert=True)

			return log_instance.id

	def _rotate_logs(self, log_limit, current_count):
		"""Handle log rotation using bulk ops."""

		# Calculate how many logs to remove
		remove_count = (
			current_count - log_limit + 1
		)  # +1 to make space for new log

		# Get IDs of oldest logs to remove
		old_log_ids = Log.objects.order_by("id").values_list("id", flat=True)[
			:remove_count
		]

		# Bulk delete old logs
		Log.objects.filter(id__in=old_log_ids).delete()
