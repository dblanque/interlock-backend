################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: core.views.logs
# Contains the ViewSet for Log related operations

# ---------------------------------- IMPORTS -----------------------------------#
### Exceptions
from core.exceptions.logs import LogTruncateMinmaxNotFound

### Models
from core.models.log import Log
from core.models.user import User

### Mixins
from .mixins.logs import LogMixin

### ViewSets
from core.views.base import BaseViewSet

### Django
from django.db import transaction

### REST Framework
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.decorators import action

### Exceptions
from core.exceptions import base as exc_base

### Others
from core.decorators.login import auth_required, admin_required
import logging
################################################################################

DBLogMixin = LogMixin()
logger = logging.getLogger(__name__)


class LogsViewSet(BaseViewSet, LogMixin):
	@auth_required
	@admin_required
	def list(self, request: Request, pk=None):
		# TODO - Add backend pagination
		user: User = request.user
		data = {}
		code = 0
		headers = {
			"id": "id",
			"logged_at": "date",
			"user": "user",
			"operation_type": "actionType",
			"log_target_class": "objectClass",
			"log_target": "affectedObject",
			"message": "extraMessage",
		}
		log_list: list[dict] = []
		date_format = {
			"iso": "%Y-%m-%dT%H:%M:%S.%f%z",
			"readable": "%Y-%m-%d %H:%M:%S",
		}
		query_set = Log.objects.all()
		for log in query_set:
			log_data = {}
			for local_header, front_header in headers.items():
				if local_header == "user":
					log_data[front_header] = getattr(log, local_header).username
				elif local_header == "logged_at":
					log_data[front_header] = getattr(
						log,
						local_header,
					).strftime(date_format["iso"])
				else:
					log_data[front_header] = getattr(log, local_header)
			log_list.append(log_data)

		return Response(
			data={
				"code": code,
				"code_msg": "ok",
				"logs": log_list,
				"headers": list(headers.values()),
			}
		)

	@action(detail=False, methods=["get"])
	@auth_required
	@admin_required
	def reset(self, request: Request, pk=None):
		user: User = request.user
		data = request.data
		code = 0

		with transaction.atomic():
			Log.objects.all().delete()

		return Response(data={"code": code, "code_msg": "ok", "data": data})

	@action(detail=False, methods=["post"])
	@auth_required
	@admin_required
	def truncate(self, request: Request, pk=None):
		user: User = request.user
		data: dict = request.data
		code = 0

		for fld in ("min","max",):
			if data.get(fld, None) is None:
				raise LogTruncateMinmaxNotFound(data={
					"detail": f"Field '{fld}' is required."
				})

			try:
				data[fld] = int(data[fld])
			except ValueError:
				raise exc_base.BadRequest(data={
					"detail": f"{fld} must be of type int or a valid numeric string."
				})

		with transaction.atomic():
			Log.objects.filter(
				id__gte=data["min"],
				id__lte=data["max"],
			).delete()

		return Response(data={"code": code, "code_msg": "ok", "data": data})
