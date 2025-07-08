from django.conf import settings


def test_debug_off():
	assert not settings.DEBUG
