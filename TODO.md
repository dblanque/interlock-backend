# Target Mid-June release
* [x] Finish High-Medium Priority items.
* [x] Finish all automated tests.
* [x] Do manual testing of all systems with the following installations.
	* [x] Standalone
	* [x] Samba LDAP
	* [x] Microsoft ADDS
* [x] Create new pgp/gpg for apt repo (with expiry).
* [x] Create .deb for apt repo key installation and updating.
* [x] Update and fix .deb package installer.
* [x] Update Public site with new screenshots.
* [x] Create Integration with PVE/GITLAB/GRAFANA documentation.
* [x] Add use-cases table to public site?
* [x] Create general video summary.
* [x] Create Installation Tutorial Video.
* [ ] Create video summary of features as LDAP Manager.
* [ ] Create video summary of features as IdP.
* [ ] Create Proxmox VE Integration Video.
* [ ] Create GitLab CE Integration Video.
* [ ] Create Grafana Integration Video.

# Post-release roadmap
* [ ] Fully fledged API Documentation.
* [ ] OpenLDAP Support.
* [ ] Add session management for OIDC (if possible).

# Tests
* [ ] core.views.oidc.CustomOidcViewSet.reject
* [ ] core.mixins.oidc.OidcAuthorizeMixin.get_reject_url
* [ ] core.views.mixins.SettingsViewMixin
	* [ ] set_value_fields - mock test
	* [ ] parse_local_setting_data - mock test
	* [ ] parse_ldap_setting_value - mock test
	* [ ] parse_ldap_setting_data - mock test
* [ ] tests for local user import with password


## Issues
### High Priority
* [ ] Update all Interlock Documentation.
* [ ] Check postinst script skip service startup if pip install is skipped.
* [ ] Fix/Check support for different response types.

### Medium Priority
* [ ] Add logging to all Application Security Group model operations.
* [ ] Add logging to all TOTP operations.
* [ ] Add all relevant endpoints for oidc to home view.

### Low Priority (Post Release)
* [ ] Implement Server-side pagination.
* [ ] Implement LDAP Group Serializer usage.
* [ ] Add Application Group LDAP Object Pruning Signal and Endpoint
* [ ] Add bool setting key for Interlock -> ALLOW_LDAP_TO_OVERRIDE_LOCAL_USERS
* [ ] Move Self endpoints to separate viewset.
* [ ] Add OIDC Prompt Features?
	* [ ] login <d>
	* [ ] consent <d>
	* [ ] select_account <n>
	* [ ] create <n>
* [ ] Improve OIDC Exception Responses to frontend
* [ ] Add rsa encryption key re-generation in settings (must de-crypt and re-encrypt data)
* [ ] Add Application Security Group Bulk actions

## Nice would-haves
* [ ] Add customizable gunicorn config
* [ ] Password Reset Requests for End Users that forget their password.
* [ ] Log OIDC Login connections
* [ ] Generate New Recovery Codes
* [ ] Directory Tree Bulk-Move
* [ ] Directory Tree Recursive Delete.
* [ ] Make DBLogMixin logging use a model reference and primary key for local data models.
* [ ] Add LDAP_DEFAULT_USER_CLASSES, LDAP_DEFAULT_GROUP_CLASSES to ldap settings.
* [ ] Add TEST Record Resolution btn to frontend dns view.
* [ ] Add "View raw object data" option on LDAP Tree.
* [ ] Add browser fingerprint model.
* [ ] Add browser fingerprint claim to simplejwt tokens.
* [ ] Remove redundant translations for card titles, use action + class with TC.
* [ ] Add "Enforce 2FA for Administrators on Interlock" option.
	* [ ] This option should disable any critical action if 2FA is not enabled.
* [ ] Add SSH capability for GPO Management.
* [ ] Allow samba password policy change from Interlock (GPO Involved).
* [ ] Test LDAP Server IPv6 Support.
* [ ] Add *copy ldap dn* button in ldap dirtree section.
* [ ] Add GUID and Display Name User fields in OpenID Connect?