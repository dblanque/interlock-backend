Target Mid-June release
* Finish High-Medium Priority items.
* Finish all automated tests
* Do manual testing of all systems with the following installations
	* Standalone
	* Samba LDAP
	* Microsoft ADDS
* Create new pgp/gpg for apt repo (with expiry)
* Create .deb for apt repo key installation and updating
* Update and fix .deb package installer
* Update Public site with new screenshots
* Create general video summary
* Create video summary of features as LDAP Manager
* Create video summary of features as IdP

# Tasks
* Finish generic endpoint tests (unauthorized, ldap disabled, etc.).
* User is_built_in <d>
* core.constants.search_attrs_builder <d>
* core.serializers.ldap <d>
* core.serializers.token
	* validate -> get_user_totp_device block
	* TokenRefreshSerializer -> validate
* core.views.mixins.SettingsViewMixin
	* set_value_fields - mock test
	* parse_local_setting_data - mock test
	* parse_ldap_setting_value - mock test
	* parse_ldap_setting_data - mock test
* fix test_cookie_jwt_refresh_valid_token <d>
* core.models.ldap_object <d>
* core.models.ldap_user <d>
* core.models.ldap_group <d>
* core.models.ldap_tree - MONDAY <d>
* core.ldap.ldap_settings - TUESDAY <d>
* core.serializers.group - THURSDAY <d>
* core.views
	* application <d>
	* application group <d>
	* auth <d>
	* home <d>
	* settings <d>
	* logs - next week <d>
	* oidc - friday <d>
	* totp - thursday? <d>
	* user - wednesday <d>
* core.decorators.login.is_axios_request <d>
* interlock_backend.server_timezone <d>
* tests for ldap user imports with placeholder password, path, no path <d>
* implement placeholder password usage onto local user import
* tests for local user import with password


## Issues
### High Priority
* Move LDAP Log Options to Interlock Settings.
* Add throttling? <d>
* Move Interlock RSA Key to class instances as a singleton. <d>
* Normalize in and out for Settings, DEFAULT_ADMIN_ENABLED and DEFAULT_ADMIN_PWD
	should be within LOCAL instead of LDAP settings in both fetch and save.
* Implement LDAP Group Serializer usage.
* Add LDAP_DEFAULT_USER_CLASSES, LDAP_DEFAULT_GROUP_CLASSES to ldap settings.
* Check TOTP support for non admin users
* Normalize API Endpoint naming and methods <d>

### Medium Priority
* Add LDAP User Syncing <d>
* Add LDAP User Purging <d>
* Add LDAP User Pruning <d>
* Add Local User Bulk Actions <d>
	* Update <d>
	* Delete <d>
	* Enable/Disable <d>
* Add Local User Import <d>
* Fix LDAP User Import on Front-end post refactor <d>
* Add logging to all Application Security Group model operations
* Add logging to all TOTP operations

### Low Priority (Post Release)
* Placeholder / CSV Password import for Local Users <d>
* Add tests for user export endpoints
* Add Application Group LDAP Object Pruning Signal and Endpoint
* Add bool setting key for Interlock -> ALLOW_LDAP_TO_OVERRIDE_LOCAL_USERS
* Move Self endpoints to separate viewset?
* Add OIDC Prompt Features?
	* login <d>
	* consent <d>
	* select_account <n>
	* create <n>
* Re-factor LDAP Import endpoint <d>
* Improve OIDC Exception Responses to frontend
* Add rsa encryption key re-generation in settings (must de-crypt and re-encrypt data)
* Add Application Security Group Bulk actions

## Nice would-haves
* Add TEST Record Resolution to frontend.
* Add "View raw object data" option on LDAP Tree.
* Add browser fingerprint model.
* Add browser fingerprint claim to simplejwt tokens.
* Remove redundant translations for card titles, use action + class with TC.
* Add "Enforce 2FA for Administrators on Interlock" option.
	* This option should disable any critical action if 2FA is not enabled.
* Add SSH capability.
* Allow samba password policy change from Interlock (GPO Involved).
* Test LDAP Server IPv6 Support.
* Add *copy ldap dn* button in ldap dirtree section.
