""" MEP MIDDLE-WARE API URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/3.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""

#  Django 
from django.conf.urls import url
from django.contrib import admin
from django.urls import path, include

# Django-rest
from rest_framework import routers
from rest_framework import permissions
from rest_framework_simplejwt import views as jwt_views
from core.views.domain import DomainViewSet

# CORE VIEWS
from core.views.token import TokenObtainPairView, TokenRefreshView
from core.views.user import UserViewSet
from core.views.organizational_unit import OrganizationalUnitViewSet
from core.views.settings_view import SettingsViewSet
from core.views.logs import LogsViewSet
from core.views.groups import GroupsViewSet
from core.views.test import TestViewSet
from core.views.record import RecordViewSet
from interlock_backend.settings import DEBUG

# Initalizes Router
router = routers.DefaultRouter()
named_view_sets = {
    r"users": UserViewSet,
    r"groups": GroupsViewSet,
    r"domain": DomainViewSet,
    r"record": RecordViewSet,
    r"ou": OrganizationalUnitViewSet,
    r"settings": SettingsViewSet,
    r"logs": LogsViewSet,
}

if DEBUG == True:
    named_view_sets.update({ r"test": TestViewSet })

[router.register(f"api/{name}", view_set, basename=name) for name, view_set in named_view_sets.items()]

# URL PATTERNS SET HERE

urlpatterns = [
    # {BASE_URL} /
    path("", include(router.urls)),

    # {BASE_URL} /admin
    path("admin/", admin.site.urls),

    # {BASE_URL} api/token/*
    path('api/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
]
