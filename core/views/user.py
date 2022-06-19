from django.core.exceptions import PermissionDenied
from rest_framework.response import Response
from .mixins.user import UserViewMixin
from rest_framework import viewsets
from rest_framework.exceptions import NotFound
from rest_framework.decorators import action

class UserViewSet(viewsets.ViewSet, UserViewMixin):

    def list(self, request, pk=None):
        raise NotFound

    def create(self, request, pk=None):
        raise NotFound

    def put(self, request, pk=None):
        raise NotFound

    def patch(self, request, pk=None):
        raise NotFound
        
    def retrieve(self, request, pk=None):
        raise NotFound

    def update(self, request, pk=None):
        raise NotFound

    def partial_update(self, request, pk=None):
        raise NotFound

    def destroy(self, request, pk=None):
        raise NotFound

    def delete(self, request, pk=None):
        raise NotFound

    @action(detail=False, methods=['get'])
    def me(self, request):
        user = request.user
        print(user.is_staff)
        if user.is_staff == False or not user:
            raise PermissionDenied
        data = {}
        code = 0
        data["username"] = request.user.username or ""
        data["first_name"] = request.user.first_name or ""
        data["last_name"] = request.user.last_name or ""
        return Response(
             data={
                'code': code,
                'code_msg': 'hardcoded_ok',
                'user': data
             }
        )