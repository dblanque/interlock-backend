import pytest
from pytest_mock import MockType
from core.ldap.connector import sync_user_relations
from core.ldap.defaults import LDAP_AUTH_SEARCH_BASE, LDAP_AUTH_USER_FIELDS, LDAP_DOMAIN


def m_user_as_ldap_attributes(m_user: dict):
	return {
		LDAP_AUTH_USER_FIELDS["username"]: m_user.username,
		"distinguishedName": m_user.dn,
		"mail": m_user.email,
	}


@pytest.mark.parametrize(
	"user_attributes, in_ldap_admin_group",
	(
		# Test cases
		# Is LDAP Main Administrator Account, attributes not synced
		(
			# user
			{
				"username": "Administrator",
				"dn": f"cn=Administrator,{LDAP_AUTH_SEARCH_BASE}",
				"email": f"admin@{LDAP_DOMAIN}",
				"is_staff": False,
				"is_superuser": False,
			},
			# in_ldap_admin_group
			False,
		),
		# Is in ADMIN_GROUP_TO_SEARCH, attributes not synced
		(
			# user
			{
				"username": "testuser",
				"dn": f"cn=testuser,{LDAP_AUTH_SEARCH_BASE}",
				"email": f"testuser@{LDAP_DOMAIN}",
				"is_staff": False,
				"is_superuser": False,
			},
			# in_ldap_admin_group
			True,
		),
		# Is in ADMIN_GROUP_TO_SEARCH, attributes are synced
		(
			# user
			{
				"username": "testuser",
				"dn": f"cn=testuser,{LDAP_AUTH_SEARCH_BASE}",
				"email": f"testuser@{LDAP_DOMAIN}",
				"is_staff": True,
				"is_superuser": True,
			},
			# in_ldap_admin_group
			True,
		),
	),
)
def test_sync_user_relations_admin_user(
	user_attributes: dict, in_ldap_admin_group, mocker, f_runtime_settings, f_connection
):
	mocker.patch("core.config.runtime.RuntimeSettings", f_runtime_settings)

	m_user: MockType = mocker.MagicMock()
	mocker.patch("core.ldap.connector.recursive_member_search", return_value=in_ldap_admin_group)

	for key, value in user_attributes.items():
		setattr(m_user, key, value)
	sync_user_relations(
		m_user, m_user_as_ldap_attributes(m_user), connection=f_connection
	)

	assert m_user.is_staff is True
	assert m_user.is_superuser is True
	m_user.save.assert_called_once()


@pytest.mark.parametrize(
	"user_attributes",
	(
		# Test cases
		# Was in ADMIN_GROUP_TO_SEARCH, attributes not synced
		{
			"username": "testuser",
			"dn": f"cn=testuser,{LDAP_AUTH_SEARCH_BASE}",
			"email": f"testuser@{LDAP_DOMAIN}",
			"is_staff": True,
			"is_superuser": True,
		},
		# Always was normal user
		{
			"username": "testuser",
			"dn": f"cn=testuser,{LDAP_AUTH_SEARCH_BASE}",
			"email": f"testuser@{LDAP_DOMAIN}",
			"is_staff": False,
			"is_superuser": False,
		},
	),
)
def test_sync_user_relations_normal_user(
	user_attributes: dict, mocker, f_runtime_settings, f_connection
):
	mocker.patch("core.config.runtime.RuntimeSettings", f_runtime_settings)

	m_user: MockType = mocker.MagicMock()
	mocker.patch("core.ldap.connector.recursive_member_search", return_value=False)

	for key, value in user_attributes.items():
		setattr(m_user, key, value)
	sync_user_relations(
		m_user, m_user_as_ldap_attributes(m_user), connection=f_connection
	)

	assert m_user.is_staff is False
	assert m_user.is_superuser is False
	m_user.save.assert_called_once()
