import pytest
from pytest_mock import MockType
from core.ldap.connector import sync_user_relations
from core.ldap.defaults import (
	LDAP_AUTH_SEARCH_BASE,
	LDAP_AUTH_USER_FIELDS,
	LDAP_DOMAIN,
)


def m_user_as_ldap_attributes(m_user: dict):
	return {
		LDAP_AUTH_USER_FIELDS["username"]: m_user.username,
		"distinguishedName": m_user.dn,
		"mail": m_user.email,
	}


@pytest.mark.parametrize(
	"user_dict, in_ldap_admin_group",
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
	user_dict: dict,
	in_ldap_admin_group,
	mocker,
	f_runtime_settings,
	f_ldap_connection,
):
	mocker.patch("core.config.runtime.RuntimeSettings", f_runtime_settings)

	m_user: MockType = mocker.MagicMock()
	mocker.patch(
		"core.ldap.connector.recursive_member_search",
		return_value=in_ldap_admin_group,
	)

	for key, value in user_dict.items():
		setattr(m_user, key, value)
	sync_user_relations(
		m_user, m_user_as_ldap_attributes(m_user), connection=f_ldap_connection
	)

	assert m_user.is_staff is True
	assert m_user.is_superuser is True
	m_user.save.assert_called_once()


def test_sync_user_relations_no_distinguished_name(mocker):
	with pytest.raises(
		ValueError,
		match="distinguishedName not present in User LDAP Attributes.",
	):
		sync_user_relations(mocker.Mock(), {}, connection=mocker.Mock())


@pytest.mark.parametrize(
	"user_dict",
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
	user_dict: dict, mocker, f_runtime_settings, f_ldap_connection
):
	mocker.patch("core.config.runtime.RuntimeSettings", f_runtime_settings)

	m_user: MockType = mocker.MagicMock()
	mocker.patch(
		"core.ldap.connector.recursive_member_search", return_value=False
	)

	for key, value in user_dict.items():
		setattr(m_user, key, value)
	sync_user_relations(
		m_user, m_user_as_ldap_attributes(m_user), connection=f_ldap_connection
	)

	assert m_user.is_staff is False
	assert m_user.is_superuser is False
	m_user.save.assert_called_once()


@pytest.fixture
def m_user_data():
	return {
		"username": "testuser",
		"dn": f"cn=testuser,{LDAP_AUTH_SEARCH_BASE}",
		"email": f"testuser@{LDAP_DOMAIN}",
		"is_staff": False,
		"is_superuser": False,
	}


def test_sync_user_relations_dn_as_tuple(
	m_user_data: dict, mocker, f_runtime_settings, f_ldap_connection
):
	mocker.patch("core.config.runtime.RuntimeSettings", f_runtime_settings)

	m_user: MockType = mocker.MagicMock()
	a_user: MockType = mocker.MagicMock()
	for key, value in m_user_data.items():
		setattr(a_user, key, value)
	m_user.username = m_user_data["username"]
	mocker.patch(
		"core.ldap.connector.recursive_member_search", return_value=False
	)

	ldap_attributes = m_user_as_ldap_attributes(a_user)
	ldap_attributes["distinguishedName"] = (
		ldap_attributes["distinguishedName"],
	)
	sync_user_relations(m_user, ldap_attributes, connection=f_ldap_connection)

	assert a_user.dn == m_user.dn
	assert m_user.is_staff is False
	assert m_user.is_superuser is False
	m_user.save.assert_called_once()
