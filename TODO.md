Target Mid-June release
* Do manual testing of all systems
* Update and fix .deb package installer
* Update Public site with new screenshots
* Create general video summary
* Create video summary of features as LDAP Manager
* Create video summary of features as IdP

# Tasks
* fix test_cookie_jwt_refresh_valid_token
* core.models.ldap_object <d>
* core.models.ldap_user <d>
* core.models.ldap_group <d>
* core.models.ldap_tree - MONDAY <d>
* core.ldap.ldap_settings - TUESDAY <d>
* core.serializers.group - THURSDAY <d>
* core.views.mixins - <d>
	* SettingsViewMixin
		* set_value_fields
		* parse_local_setting_data
		* parse_ldap_setting_value
		* parse_ldap_setting_data
* core.views
	* application <t> - gotta do mocking
	* application group <t> - gotta do mocking
	* auth <d>
	* home <d>
	* settings <d>
	* logs - next week
	* oidc - friday?
	* totp - thursday?
	* user - wednesday <d>

## Issues
### High Priority
* Move Interlock RSA Key to class instances as a singleton. <d>
* Normalize in and out for Settings, DEFAULT_ADMIN_ENABLED and DEFAULT_ADMIN_PWD
	should be within LOCAL instead of LDAP settings in both fetch and save.
* Implement LDAP Group Serializer usage.
* Add LDAP_DEFAULT_USER_CLASSES, LDAP_DEFAULT_GROUP_CLASSES to ldap settings.
* Check TOTP support for non admin users
* Add Application Group LDAP Object Pruning
* Normalize API Endpoint naming and methods

### Medium Priority
* Add LDAP User Syncing <d>
* Add LDAP User Purging <d>
* Add LDAP User Pruning <d>
* Add Local User/ASG bulk actions
* Add Local User Import/Export
* Add LDAP User Export

### Low Priority
* Add OIDC Prompt Features?
	* login <d>
	* consent <d>
	* select_account <n>
	* create <n>
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
