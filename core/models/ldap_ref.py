from core.models.base import BaseModel
from django.db import models
from core.constants.attrs.ldap import LDAP_ATTR_DN, LDAP_ATTR_SECURITY_ID
from core.constants.attrs.local import LOCAL_ATTR_DN, LOCAL_ATTR_SECURITY_ID
from core.type_hints.connector import LDAPConnectionProtocol
from core.ldap.filter import LDAPFilter
from core.config.runtime import RuntimeSettings
from core.utils.main import getldapattr
from core.ldap.security_identifier import SID
from ldap3 import Entry as LDAPEntry


class LdapRef(BaseModel):
	distinguished_name = models.CharField(null=False, blank=False, unique=True)
	object_security_id_bytes = models.BinaryField(
		null=False,
		blank=False,
		unique=True,
	)
	object_security_id = models.CharField(
		null=False,
		blank=False,
		unique=True,
	)

	class Meta:
		db_table = "core_ldap_reference"

	def get_relative_id(self) -> int:
		"""Returns SID Sub-authority Count"""
		if not self.object_security_id:
			# Fallback to bytes
			if not self.object_security_id_bytes:
				return 0
			sid = SID(self.object_security_id_bytes)
			return int(sid.subauthorities[-1])
		rid = self.object_security_id.split("-")[-1]
		return int(rid)

	@property
	def object_relative_id(self) -> int:
		return self.get_relative_id()

	@staticmethod
	def get_dn_field() -> str:
		return RuntimeSettings.LDAP_FIELD_MAP.get(LOCAL_ATTR_DN, LDAP_ATTR_DN)

	@staticmethod
	def get_sid_field() -> str:
		return RuntimeSettings.LDAP_FIELD_MAP.get(
			LOCAL_ATTR_SECURITY_ID,
			LDAP_ATTR_SECURITY_ID,
		)

	@classmethod
	def get_entry_from_ldap(
		cls,
		connection: LDAPConnectionProtocol | None,
		pk: str,
		pk_ident: str | None = None,
	) -> LDAPEntry | None:
		"""
		Fetch LdapRef back-end entry from Security ID or specified primary key
		identifier.
		"""
		if not connection:
			raise ValueError("connection is a required value.")
		if not pk:
			raise ValueError("pk is a required value.")
		if not pk_ident:
			pk_ident = cls.get_sid_field()
		if pk_ident not in [
			LOCAL_ATTR_DN,
			LOCAL_ATTR_SECURITY_ID,
			cls.get_sid_field(),
			cls.get_dn_field(),
		]:
			raise ValueError("pk_ident must be a valid LDAP_PK_CHOICES value")
		connection.search(
			search_base=RuntimeSettings.LDAP_AUTH_SEARCH_BASE,
			search_filter=LDAPFilter.eq(pk_ident, pk).to_string(),
			attributes=[cls.get_dn_field(), cls.get_sid_field()],
			size_limit=1,
		)
		return connection.entries[0] if connection.entries else None

	@classmethod
	def get_instance_from_ldap(
		cls,
		distinguished_name: str | None,
		connection: LDAPConnectionProtocol | None,
	) -> "LdapRef | None":
		"""
		Fetch corresponding LDAP Entry by Distinguished Name and create its
		LdapRef Instance in local database.
		"""
		if not connection:
			raise ValueError("connection is a required value.")
		if not distinguished_name:
			raise ValueError("distinguished_name is a required value.")

		result_entry = cls.get_entry_from_ldap(
			connection=connection,
			pk=distinguished_name,
			pk_ident=cls.get_dn_field(),
		)
		if not result_entry:
			return None
		entry_sid = getldapattr(result_entry, cls.get_sid_field(), None)
		if not entry_sid:
			return None
		return cls(
			distinguished_name=distinguished_name,
			object_security_id_bytes=entry_sid.value,
			object_security_id=str(SID(entry_sid.value)),
		)

	def refresh_from_ldap(
		self,
		connection: LDAPConnectionProtocol | None,
	) -> bool:
		result_entry = self.get_entry_from_ldap(
			connection=connection, pk=self.object_security_id
		)
		if not result_entry:
			return False

		sid_exc = None
		try:
			entry_sid = getldapattr(result_entry, self.get_sid_field(), None)
			entry_sid = SID(entry_sid.value)
		except Exception as e:
			sid_exc = e
			pass
		if not entry_sid or (str(entry_sid) != self.object_security_id):
			if sid_exc:
				raise Exception("Entry SID Mis-match.") from sid_exc
			raise Exception("Entry SID Mis-match.")
		self.distinguished_name = result_entry.entry_dn
		return True

	def prune(self, connection: LDAPConnectionProtocol | None) -> bool:
		"""Delete LdapRef if it cannot be fetched from LDAP Back-end.

		Returns:
			bool: Object deleted."""
		if not self.get_entry_from_ldap(
			connection=connection,
			pk=self.object_security_id,
		):
			self.delete_permanently()
			return True
		return False

	def refresh_or_prune(
		self,
		connection: LDAPConnectionProtocol | None,
	) -> bool:
		"""
		Refreshes LdapRef DN or prunes it from Local DB.

		Returns True if refreshed, False if pruned.
		"""
		if not self.refresh_from_ldap(connection=connection):
			if self.prune(connection=connection):
				return False
		return True
