# Target Mid-June release
* Finish High-Medium Priority items.
* Finish all automated tests.
* Do manual testing of all systems with the following installations.
	* Standalone
	* Samba LDAP
	* Microsoft ADDS
* Create new pgp/gpg for apt repo (with expiry).
* Create .deb for apt repo key installation and updating.
* Update and fix .deb package installer.
* Update Public site with new screenshots.
* Add use-cases table to public site.
* Create general video summary.
* Create video summary of features as LDAP Manager.
* Create video summary of features as IdP.

# Post-release roadmap
* Fully fledged API Documentation
* OpenLDAP Support
* Add session management for OIDC (if possible)

# Tests
* core.views.mixins.SettingsViewMixin
	* set_value_fields - mock test
	* parse_local_setting_data - mock test
	* parse_ldap_setting_value - mock test
	* parse_ldap_setting_data - mock test
* tests for local user import with password


## Issues
### High Priority
* Add re-openable disclaimer in DNS View:
	* Wait for ttl of zone to check dns resolution
	* Beware of enabling Legacy LDAP DNS if using an older Active Directory
* Implement LDAP Group Serializer usage.
* Add LDAP_DEFAULT_USER_CLASSES, LDAP_DEFAULT_GROUP_CLASSES to ldap settings.
* Check TOTP support for non admin users.

### Medium Priority
* Add logging to all Application Security Group model operations.
* Add logging to all TOTP operations.

### Low Priority (Post Release)
* Add Application Group LDAP Object Pruning Signal and Endpoint
* Add bool setting key for Interlock -> ALLOW_LDAP_TO_OVERRIDE_LOCAL_USERS
* Move Self endpoints to separate viewset.
* Add OIDC Prompt Features?
	* login <d>
	* consent <d>
	* select_account <n>
	* create <n>
* Improve OIDC Exception Responses to frontend
* Add rsa encryption key re-generation in settings (must de-crypt and re-encrypt data)
* Add Application Security Group Bulk actions

## Nice would-haves
* Add TEST Record Resolution btn to frontend dns view.
* Add "View raw object data" option on LDAP Tree.
* Add browser fingerprint model.
* Add browser fingerprint claim to simplejwt tokens.
* Remove redundant translations for card titles, use action + class with TC.
* Add "Enforce 2FA for Administrators on Interlock" option.
	* This option should disable any critical action if 2FA is not enabled.
* Add SSH capability for GPO Management.
* Allow samba password policy change from Interlock (GPO Involved).
* Test LDAP Server IPv6 Support.
* Add *copy ldap dn* button in ldap dirtree section.
