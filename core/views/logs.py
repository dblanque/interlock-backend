from rest_framework.response import Response
from core.models.settings_model import Setting
from .mixins.logs import LogMixin
from rest_framework.decorators import action
from interlock_backend.ldap.encrypt import validateUser
from core.views.base import BaseViewSet
from core.models.log import Log
from core.exceptions.logs import LogTruncateMinmaxNotFound
import logging

logger = logging.getLogger(__name__)

class LogsViewSet(BaseViewSet, LogMixin):
    queryset = Setting.objects.all()

    def list(self, request, pk=None):
        user = request.user
        validateUser(request=request, requestUser=user)
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
        querySet = Log.objects.all()
        for log in querySet:
            logDict = {}
            for h in headers:
                if h == 'user':
                    logDict[h] = getattr(log, h).username
                elif h == 'date':
                    logDict[h] = getattr(log, 'logged_at').strftime("%Y-%m-%d %H:%M:%S")
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
    def reset(self, request, pk=None):
        user = request.user
        validateUser(request=request, requestUser=user)
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
    def truncate(self, request, pk=None):
        user = request.user
        validateUser(request=request, requestUser=user)
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
