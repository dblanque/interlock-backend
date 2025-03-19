import pytest
from unittest.mock import MagicMock
from core.ldap.connector import sync_user_relations
from core.ldap.defaults import LDAP_AUTH_SEARCH_BASE, LDAP_AUTH_USER_FIELDS, LDAP_DOMAIN

def m_user_as_ldap_attributes(m_user: dict):
	return {
		LDAP_AUTH_USER_FIELDS["username"]: m_user.username,
		"distinguishedName": m_user.dn,
		"mail": m_user.email,
	}

@pytest.mark.parametrize(
	"user_attributes, in_ldap_admin_group, expects_admin",
	(
		# Test cases
		# Is LDAP Main Administrator Account, attributes not synced
		(
			# user
			{
				"username":"Administrator",
				"dn":f"cn=Administrator,{LDAP_AUTH_SEARCH_BASE}",
				"email":f"admin@{LDAP_DOMAIN}",
				"is_staff": False,
				"is_superuser": False,
			},
			# in_ldap_admin_group
			False,
			# expects_admin
			True
		),
		# Is in ADMIN_GROUP_TO_SEARCH, attributes not synced
		(
			# user
			{
				"username":"testuser",
				"dn":f"cn=testuser,{LDAP_AUTH_SEARCH_BASE}",
				"email":f"testuser@{LDAP_DOMAIN}",
				"is_staff": False,
				"is_superuser": False,
			},
			# in_ldap_admin_group
			True,
			# expects_admin
			True
		),
		# Is in ADMIN_GROUP_TO_SEARCH, attributes are synced
		(
			# user
			{
				"username":"testuser",
				"dn":f"cn=testuser,{LDAP_AUTH_SEARCH_BASE}",
				"email":f"testuser@{LDAP_DOMAIN}",
				"is_staff": True,
				"is_superuser": True,
			},
			# in_ldap_admin_group
			True,
			# expects_admin
			True
		),
		# Is not admin
		(
			# user
			{
				"username":"testuser",
				"dn":f"cn=testuser,{LDAP_AUTH_SEARCH_BASE}",
				"email":f"testuser@{LDAP_DOMAIN}",
				"is_staff": False,
				"is_superuser": False,
			},
			# in_ldap_admin_group
			False,
			# expects_admin
			False
		),
	)
)
def test_sync_user_relations(
	user_attributes: dict, in_ldap_admin_group, expects_admin,
	mocker
):
	m_runtime_settings: MagicMock = mocker.MagicMock()
	m_runtime_settings.LDAP_AUTH_USER_FIELDS = LDAP_AUTH_USER_FIELDS
	mocker.patch(
		"core.config.runtime.RuntimeSettings",
		return_value=m_runtime_settings
	)

	m_connection: MagicMock = mocker.MagicMock()
	m_user_mock: MagicMock = mocker.MagicMock()
	mocker.patch(
		"core.ldap.connector.recursive_member_search",
		return_value=in_ldap_admin_group
	)

	for key, value in user_attributes.items():
		setattr(m_user_mock, key, value)
	sync_user_relations(
		m_user_mock,
		m_user_as_ldap_attributes(m_user_mock),
		connection=m_connection
	)

	if expects_admin:
		assert m_user_mock.is_staff is True
		assert m_user_mock.is_superuser is True
	else:
		assert m_user_mock.is_staff is False
		assert m_user_mock.is_superuser is False
	m_user_mock.save.assert_called_once()
