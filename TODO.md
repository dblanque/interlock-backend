# Create/Complete/Fix tests for
* core.models.ldap_object <d>
* core.models.ldap_user <d>
* core.models.ldap_group <d>
* core.models.ldap_tree - MONDAY <d>
* core.ldap.ldap_settings - TUESDAY
* core.serializers.group - THURSDAY
* core.views.mixins.domain - FRIDAY
* core.views - NEXT WEEK

# To test manually
* Add OIDC Consent Features <t>
* Add OIDC TOTP Features for Users <t>
* Add logging to all Application model operations <t>

## Issues
* Add LDAP_DEFAULT_USER_CLASSES, LDAP_DEFAULT_GROUP_CLASSES to ldap settings
* Move Interlock RSA Key to class instances as a singleton. <d>
* Add local user/asg bulk actions
* Add OIDC Prompt Features?
	* login
	* consent
	* select_account
	* create
* Add rsa encryption key re-generation in settings (must de-crypt and re-encrypt data)
* Add logging to all Application Security Group model operations
* Add logging to all TOTP operations
* Add LDAP User Syncing <d>
* Add LDAP User Purging <d>
* Add LDAP User Pruning <d>
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
