import pytest
from django.db import connection


@pytest.mark.django_db
def test_database_name_correctness():
	assert connection.settings_dict["NAME"] == "test_interlockdb"
