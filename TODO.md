## 2025/04/29
* Map User LDAP fields to local django standards?
	* may involve massive front-end modification
* Map Group LDAP Fields to local django standards?
	* may involve massive front-end modification
* Add serializer to ldap user viewset endpoints
* Add serializer to ldap group viewset endpoints
* Add serializer to ldap ou viewset endpoints

# To test manually
* Add OIDC Consent Features <t>
* Add OIDC TOTP Features for Users <t>
* Add logging to all Application model operations <t>

## Issues
* Move interlock_rsa to class instances
* Add local user/asg bulk actions
* Add OIDC Prompt Features?
	* login
	* consent
	* select_account
	* create
* Add rsa encryption key re-generation in settings (must de-crypt and re-encrypt data)
* Add logging to all Application Security Group model operations
* Add logging to all TOTP operations
* Add LDAP User Pruning
* Add Application Group LDAP Object Pruning
* Add exception chaining where necessary
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
