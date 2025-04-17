## Urgent Issues
* Move RuntimeSettings to class instances instead of global import
* Move interlock_rsa to class instances
* Create admin_required decorator <d>
* Fix refreshing on ApplicationForm / ApplicationDialog <d>
* Change tabs to sidebar <d>
* Create Applications model <d>
* Re-factor enable/disable LDAP Users into single endpoint <d>
* Fix redundant usage of user.dn user.encryptedPassword in LDAPConnector calls <d>
* Re-factor filter building in all LDAP views to classes <d>
* Add Application Client Response Type Management <d>
* Add Application Endpoints Serialization <d>
* Add local user/group management for Interlock as IdP
	* Create <d>
	* Update <d>
	* Read <d>
	* Delete <d>
	* Change Password <d>
	* Self Update <d>
	* Self Change Password <d>
	* End User Support <d>
	* Bulk Actions (Low Priority)
* Create groups model (support local and foreign, e.g: LDAP) <d>
* Add Application Groups <d>
	* Fetch Current LDAP Groups <d>
	* Fetch Local Groups <d>
* Remove LDAP Groups DNs from Application Groups when destroyed. <d>
* Add OIDC Consent Features <t>
* Add OIDC TOTP Features for Users <t>
* Add Warning when enabling/disabling Application Group <d>
* Add OIDC Prompt Features?
	* login
	* consent
	* select_account
	* create
* Add OIDC Group Validation for Application <d>
* Fix dropdown z-index on settings card <d>
* Change login view to use list of strings instead of showLogin,showOIDC,showTotp <d>
* Add intercept_data decorator for building fixtures <d>
* Add Delete TOTP for Django Users VUE Admin View <d>
* Add bool for Interlock LDAP Backend Enabled/disabled in settings <d>
* Add rsa encryption key re-generation in settings (must de-crypt and re-encrypt data)
* Add home dashboard <d>
	* local user/group count <d>
	* openid well-known data <d>
	* ldap users count (synced only) <d>
	* ldap backend status <d>
	* ldap config data <d>
* Add logging to all Application model operations <t>
* Add logging to all Application Security Group model operations
* Add logging to all TOTP operations
* Add LDAP User Pruning
* Add Application Group LDAP Object Pruning
* Add exception chaining
* Check totp support for non admin users
* Add Local User Import/Export
* Add LDAP User Export

## Other Tasks
* Implement (ldap3.utils.dn) safe_rdn, safe_dn, parse_dn, etc. usage where required.
* Add browser fingerprint model
* Add browser fingerprint claim to simplejwt tokens
* Remove redundant translations for card titles, use action + class with TC
* Add "Enforce 2FA for Administrators on Interlock" option
	* This option should disable any critical action if 2FA is not enabled.
* Add "View raw object data" option on LDAP Tree
* Add support for TOTP enable/disable for other users from admin/users
* Refactor OU viewset
* Add SSH capability
* Move redundant DNS record parsing to parse_entry_record function in Mixin
* Allow samba password policy change from Interlock (GPO Involved)
* Test LDAP Server IPv6 Support
* Add *copy ldap dn* button in ldap dirtree section
