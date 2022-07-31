from rest_framework.response import Response
from core.models.settings_model import Setting
from .mixins.logs import LogMixin
from rest_framework.decorators import action
from interlock_backend.ldap.encrypt import validateUser
from core.views.base import BaseViewSet
from core.models.log import Log
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

        print('resetLogs')

        return Response(
             data={
                'code': code,
                'code_msg': 'ok',
                'data': data
             }
        )
