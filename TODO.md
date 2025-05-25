Target Mid-June release
* Do manual testing of all systems
* Update and fix .deb package installer
* Update Public site with new screenshots
* Create general video summary
* Create video summary of features as LDAP Manager
* Create video summary of features as IdP

# Tasks
* core.models.ldap_object <d>
* core.models.ldap_user <d>
* core.models.ldap_group <d>
* core.models.ldap_tree - MONDAY <d>
* core.ldap.ldap_settings - TUESDAY <d>
* core.serializers.group - THURSDAY <d>
* core.views.mixins - <d>
* core.views - Tuesday - Friday

## Issues
### High Priority
* Move Interlock RSA Key to class instances as a singleton. <d>
* Implement LDAP Group Serializer usage.
* Add LDAP_DEFAULT_USER_CLASSES, LDAP_DEFAULT_GROUP_CLASSES to ldap settings.
* Check TOTP support for non admin users
* Add Application Group LDAP Object Pruning

### Medium Priority
* Add LDAP User Syncing <d>
* Add LDAP User Purging <d>
* Add LDAP User Pruning <d>
* Add self-registry availability with captcha requirement.
	* USER_SELF_REGISTRY_OPTIONS
		* CAPTCHA KEY
		* CAPTCHA SITE
		* ALLOWED DOMAINS (ALL IF WILDCARD)
* Add local User/ASG bulk actions
* Add Local User Import/Export
* Add LDAP User Export

### Low Priority
* Add OIDC Prompt Features?
	* login
	* consent
	* select_account
	* create
* Add logging to all Application Security Group model operations
* Add logging to all TOTP operations
* Add rsa encryption key re-generation in settings (must de-crypt and re-encrypt data)

## Nice would-haves
* Add browser fingerprint model.
* Add browser fingerprint claim to simplejwt tokens.
* Remove redundant translations for card titles, use action + class with TC.
* Add "Enforce 2FA for Administrators on Interlock" option.
	* This option should disable any critical action if 2FA is not enabled.
* Add "View raw object data" option on LDAP Tree.
* Add SSH capability.
* Allow samba password policy change from Interlock (GPO Involved).
* Test LDAP Server IPv6 Support.
* Add *copy ldap dn* button in ldap dirtree section.
