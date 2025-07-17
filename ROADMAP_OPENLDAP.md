# OpenLDAP Roadmap Notes
Schema docs: <http://www.phpldaptools.com/reference/Default-Schema-Attributes/#the-openldap-schema>

* [ ] Contemplate schema changes from ADDS/Samba to default OpenLDAP for:
  * [ ] Users
  * [ ] Groups
  * [ ] OUs
* [ ] Disable DNS for OpenLDAP.
* [ ] Contemplate lack of SID availability in OpenLDAP by default (LdapRef).
  * Use entryUUID.
* [ ] Fix Dirtree default filtering (OpenLDAP does not use objectCategory).