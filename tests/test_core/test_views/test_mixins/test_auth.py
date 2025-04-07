import pytest
from core.models.user import User
from django.contrib.auth.models import AnonymousUser
from django.http import HttpRequest
from rest_framework.response import Response
from rest_framework import status
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework_simplejwt.tokens import AccessToken, RefreshToken
from core.exceptions.base import AccessTokenInvalid, RefreshTokenExpired
from core.views.mixins.auth import (
    RemoveTokenResponse,
    CookieJWTAuthentication,
    EMPTY_TOKEN,
    BAD_LOGIN_COOKIE_NAME,
    BAD_LOGIN_LIMIT,
)

##########################################################################################
######################################## Fixtures ########################################
##########################################################################################

@pytest.fixture
def mock_request():
    """Fixture providing a mock HttpRequest"""
    request = HttpRequest()
    request.COOKIES = {}
    return request

@pytest.fixture
def jwt_settings(settings):
    """Fixture to configure JWT settings for testing"""
    settings.SIMPLE_JWT = {
        "AUTH_COOKIE_NAME": "access_token",
        "REFRESH_COOKIE_NAME": "refresh_token",
        "AUTH_COOKIE_SAME_SITE": "Lax",
        "AUTH_COOKIE_DOMAIN": None,
    }
    return settings.SIMPLE_JWT

@pytest.fixture
def test_user(db):
    """Fixture creating a test user in the database"""
    return User.objects.create_user(
        username="testuser",
        password="testpass",
        email="test@example.com"
    )

@pytest.fixture
def valid_access_token(test_user):
    """Fixture providing a valid access token with user association"""
    token = AccessToken.for_user(test_user)
    return str(token)

@pytest.fixture
def valid_refresh_token(test_user):
    """Fixture providing a valid refresh token with user association"""
    token = RefreshToken.for_user(test_user)
    return str(token)

@pytest.fixture
def cookie_auth():
    """Fixture providing an instance of CookieJWTAuthentication"""
    return CookieJWTAuthentication()

##########################################################################################
############################# Tests for RemoveTokenResponse ##############################
##########################################################################################

def test_remove_token_response_basic(mock_request, jwt_settings):
    response = RemoveTokenResponse(mock_request)
    
    assert isinstance(response, Response)
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert "access_token" in response.cookies
    assert response.cookies["access_token"].value == "expired"
    assert "refresh_token" not in response.cookies
    assert response.data["remaining_login_count"] == BAD_LOGIN_LIMIT

def test_remove_token_response_with_refresh(mock_request, jwt_settings):
    response = RemoveTokenResponse(mock_request, remove_refresh=True)
    
    assert "refresh_token" in response.cookies
    assert response.cookies["refresh_token"].value == "expired"

def test_remove_token_response_with_bad_login_count_zero(mock_request, jwt_settings):
    response = RemoveTokenResponse(mock_request, bad_login_count=True)
    
    assert BAD_LOGIN_COOKIE_NAME in response.cookies
    assert response.cookies[BAD_LOGIN_COOKIE_NAME].value == "1"
    assert response.data["remaining_login_count"] == BAD_LOGIN_LIMIT - 1

def test_remove_token_response_with_bad_login_count_existing(mock_request, jwt_settings):
    mock_request.COOKIES[BAD_LOGIN_COOKIE_NAME] = "2"
    response = RemoveTokenResponse(mock_request, bad_login_count=True)
    
    assert response.cookies[BAD_LOGIN_COOKIE_NAME].value == "3"
    assert response.data["remaining_login_count"] == BAD_LOGIN_LIMIT - 3

def test_remove_token_response_with_bad_login_count_max(mock_request, jwt_settings):
    mock_request.COOKIES[BAD_LOGIN_COOKIE_NAME] = str(BAD_LOGIN_LIMIT)
    response = RemoveTokenResponse(mock_request, bad_login_count=True)
    
    assert response.cookies[BAD_LOGIN_COOKIE_NAME].value == "0"
    assert response.data["remaining_login_count"] == BAD_LOGIN_LIMIT

def test_remove_token_response_with_invalid_bad_login_count(mock_request, jwt_settings):
    mock_request.COOKIES[BAD_LOGIN_COOKIE_NAME] = "invalid"
    response = RemoveTokenResponse(mock_request, bad_login_count=True)
    
    assert response.cookies[BAD_LOGIN_COOKIE_NAME].value == "1"
    assert response.data["remaining_login_count"] == BAD_LOGIN_LIMIT - 1

##########################################################################################
############################# Tests for CookieJWTAuthentication ##########################
##########################################################################################

def test_cookie_jwt_authenticate_no_token(cookie_auth: CookieJWTAuthentication, mock_request):
    user, token = cookie_auth.authenticate(mock_request)
    
    assert isinstance(user, AnonymousUser)
    assert token == EMPTY_TOKEN

def test_cookie_jwt_authenticate_expired_token(cookie_auth: CookieJWTAuthentication, mock_request, jwt_settings):
    mock_request.COOKIES[jwt_settings["AUTH_COOKIE_NAME"]] = "expired"
    user, token = cookie_auth.authenticate(mock_request)
    
    assert isinstance(user, AnonymousUser)
    assert token == EMPTY_TOKEN

def test_cookie_jwt_authenticate_empty_token(cookie_auth: CookieJWTAuthentication, mock_request, jwt_settings):
    mock_request.COOKIES[jwt_settings["AUTH_COOKIE_NAME"]] = ""
    user, token = cookie_auth.authenticate(mock_request)
    
    assert isinstance(user, AnonymousUser)
    assert token == EMPTY_TOKEN

def test_cookie_jwt_authenticate_valid_token(cookie_auth: CookieJWTAuthentication, mock_request, jwt_settings, valid_access_token, test_user):
    mock_request.COOKIES[jwt_settings["AUTH_COOKIE_NAME"]] = valid_access_token
    user, token = cookie_auth.authenticate(mock_request)

    assert user.id == test_user.id
    assert isinstance(token, AccessToken)
    assert len(token.__str__()) > 0

def test_cookie_jwt_authenticate_invalid_token(cookie_auth: CookieJWTAuthentication, mock_request, jwt_settings):
    mock_request.COOKIES[jwt_settings["AUTH_COOKIE_NAME"]] = "invalid.token.here"
    
    with pytest.raises(AccessTokenInvalid):
        cookie_auth.authenticate(mock_request)

def test_cookie_jwt_refresh_no_token(cookie_auth: CookieJWTAuthentication, mock_request):
    with pytest.raises(RefreshTokenExpired):
        cookie_auth.refresh(mock_request)

def test_cookie_jwt_refresh_expired_token(cookie_auth: CookieJWTAuthentication, mock_request, jwt_settings):
    mock_request.COOKIES[jwt_settings["REFRESH_COOKIE_NAME"]] = "expired"
    
    with pytest.raises(RefreshTokenExpired):
        cookie_auth.refresh(mock_request)

def test_cookie_jwt_refresh_empty_token(cookie_auth: CookieJWTAuthentication, mock_request, jwt_settings):
    mock_request.COOKIES[jwt_settings["REFRESH_COOKIE_NAME"]] = ""
    
    with pytest.raises(RefreshTokenExpired):
        cookie_auth.refresh(mock_request)

def test_cookie_jwt_refresh_valid_token(cookie_auth: CookieJWTAuthentication, mock_request, jwt_settings, valid_refresh_token):
    mock_request.COOKIES[jwt_settings["REFRESH_COOKIE_NAME"]] = valid_refresh_token
    access_token, refresh_token = cookie_auth.refresh(mock_request)
    
    # Verify the tokens are valid by attempting to decode them
    AccessToken(access_token.token)
    RefreshToken(refresh_token)

def test_cookie_jwt_refresh_invalid_token(cookie_auth: CookieJWTAuthentication, mock_request, jwt_settings):
    mock_request.COOKIES[jwt_settings["REFRESH_COOKIE_NAME"]] = "invalid.token.here"
    
    with pytest.raises(RefreshTokenExpired):
        cookie_auth.refresh(mock_request)

def test_cookie_jwt_refresh_token_error_handling(mocker, cookie_auth: CookieJWTAuthentication, mock_request, jwt_settings, valid_refresh_token):
    mock_request.COOKIES[jwt_settings["REFRESH_COOKIE_NAME"]] = valid_refresh_token
    mocker.patch.object(RefreshToken, '__init__', side_effect=TokenError('Test error'))
    
    with pytest.raises(RefreshTokenExpired):
        cookie_auth.refresh(mock_request)

def test_cookie_jwt_authenticate_generic_error_handling(mocker, cookie_auth: CookieJWTAuthentication, mock_request, jwt_settings):
    mock_request.COOKIES[jwt_settings["AUTH_COOKIE_NAME"]] = "valid.token"
    mocker.patch.object(AccessToken, '__init__', side_effect=Exception('Generic error'))
    
    with pytest.raises(Exception):
        cookie_auth.authenticate(mock_request)
