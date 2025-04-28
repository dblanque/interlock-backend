from ldap3 import Connection, Server, ServerPool, Entry
from ldap3.extend import (
	ExtendedOperationsRoot,
	MicrosoftExtendedOperations,
	StandardExtendedOperations,
	NovellExtendedOperations,
)
from typing import overload

class LDAPConnectionProtocol(Connection):
	entries: list[Entry] | None
	extend: "LDAPExtendedOperations"
	server_pool: "LDAPServerPool"

class LDAPExtendedOperations(ExtendedOperationsRoot):
	microsoft: MicrosoftExtendedOperations
	standard: StandardExtendedOperations
	novell: NovellExtendedOperations

class LDAPServerPool(ServerPool):
	servers: list["LDAPServer"]

	@overload
	def get_current_server(self, connection) -> "LDAPServer": ...

class LDAPServer(Server):
	pass
