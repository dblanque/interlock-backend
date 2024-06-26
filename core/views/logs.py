################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: core.views.logs
# Contains the ViewSet for Log related operations

#---------------------------------- IMPORTS -----------------------------------#
### Exceptions
from core.exceptions.logs import LogTruncateMinmaxNotFound

### Models
from core.models.log import Log

### Mixins
from .mixins.logs import LogMixin

### ViewSets
from core.views.base import BaseViewSet

### REST Framework
from rest_framework.response import Response
from rest_framework.decorators import action

### Others
from core.decorators.login import auth_required
import logging
################################################################################

DBLogMixin = LogMixin()
logger = logging.getLogger(__name__)

class LogsViewSet(BaseViewSet, LogMixin):

	@auth_required()
	def list(self, request, pk=None):
		user = request.user
		data = {}
		code = 0
		headers = [
			'id',
			'date',
			'user',
			'actionType',
			'objectClass',
			'affectedObject',
			'extraMessage'
		]
		response_list = []
		date_format = {
			'iso': '%Y-%m-%dT%H:%M:%S.%f%z',
			'readable': "%Y-%m-%d %H:%M:%S"
		}
		querySet = Log.objects.all()
		for log in querySet:
			logDict = {}
			for h in headers:
				if h == 'user':
					logDict[h] = getattr(log, h).username
				elif h == 'date':
					logDict[h] = getattr(log, 'logged_at').strftime(date_format['iso'])
				elif h == 'affectedObject':
					logDict[h] = getattr(log, h)
				else:
					logDict[h] = getattr(log, h)
			response_list.append(logDict)

		return Response(
			 data={
				'code': code,
				'code_msg': 'ok',
				'logs': response_list,
				'headers': headers
			 }
		)

	@action(detail=False, methods=['get'])
	@auth_required()
	def reset(self, request, pk=None):
		user = request.user
		data = request.data
		code = 0

		Log.objects.all().delete()

		return Response(
			 data={
				'code': code,
				'code_msg': 'ok',
				'data': data
			 }
		)

	@action(detail=False, methods=['post'])
	@auth_required()
	def truncate(self, request, pk=None):
		user = request.user
		data = request.data
		code = 0

		thresholdMin = data['min']
		thresholdMax = data['max']

		if thresholdMin is None or thresholdMax is None:
			raise LogTruncateMinmaxNotFound

		Log.objects.filter(id__gte=thresholdMin,id__lte=thresholdMax).delete()

		return Response(
			 data={
				'code': code,
				'code_msg': 'ok',
				'data': data
			 }
		)
