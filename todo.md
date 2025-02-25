## Urgent Issues
* Migrate usage of Fernet to encrypt to use AES/RSA instead.
* Add OIDC Support
* Add self tab for admin users
* check totp support for non admin users
* add oidc client support
* add native user/group management for Interlock as IdP
* change tabs to sidebar
* create applications model
	* FK to groups
* create groups model (support local and foreign, e.g: LDAP)
* add backend provider group sync feature
* add ldap user pruning
* add home dashboard
	* local user/group count
	* ldap users count (synced only)
	* ldap backend status
	* ldap config data

## Other Tasks
* Add "Enforce 2FA for Administrators on Interlock" option
	* This option should disable any critical action if 2FA is not enabled.
* Add "View raw object data" option on LDAP Tree
* Make the frontend convert log dates from UTC to local TZ <done>
* Fix restore default values delay on settings card <done>
* Add support for TOTP enable/disable for other users from admin/users
* Refactor OU viewset
* Add SSH capability
* Move redundant DNS record parsing to parse_entry_record function in Mixin
* Allow samba password policy change from Interlock (GPO Involved)
* Test LDAP Server IPv6 Support
* Add *copy ldap dn* button in ldap dirtree section
