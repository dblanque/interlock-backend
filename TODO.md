# Long term
* Re-factor LDAPObjectUser to normalize LDAP Attributes to local map
* Re-factor LDAPObjectGroup to normalize LDAP Attributes to local map
* Re-factor LDAPObjects to normalize LDAP Attributes to local map

# Check after re-factor
* User CRUD
* User Bulk OPS
* Group CRUD
* Dirtree Operations
* DNS Operations

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
* Add SSH capability
* Allow samba password policy change from Interlock (GPO Involved)
* Test LDAP Server IPv6 Support
* Add *copy ldap dn* button in ldap dirtree section
