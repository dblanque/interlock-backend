# Generated by Django 4.2.4 on 2024-04-03 18:37

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0005_ldapcache_to_db'),
    ]

    operations = [
        migrations.AlterField(
            model_name='ldappreset',
            name='label',
            field=models.CharField(max_length=64, verbose_name='label'),
        ),
        migrations.AlterField(
            model_name='ldapsetting',
            name='name',
            field=models.CharField(choices=[('LDAP_AUTH_URL', 'lds_ldap_auth_url'), ('LDAP_DOMAIN', 'lds_ldap_domain'), ('LDAP_LOG_MAX', 'lds_ldap_log_max'), ('LDAP_LOG_READ', 'lds_ldap_log_read'), ('LDAP_LOG_CREATE', 'lds_ldap_log_create'), ('LDAP_LOG_UPDATE', 'lds_ldap_log_update'), ('LDAP_LOG_DELETE', 'lds_ldap_log_delete'), ('LDAP_LOG_OPEN_CONNECTION', 'lds_ldap_log_open_connection'), ('LDAP_LOG_CLOSE_CONNECTION', 'lds_ldap_log_close_connection'), ('LDAP_LOG_LOGIN', 'lds_ldap_log_login'), ('LDAP_LOG_LOGOUT', 'lds_ldap_log_logout'), ('LDAP_AUTH_USE_SSL', 'lds_ldap_auth_use_ssl'), ('LDAP_AUTH_USE_TLS', 'lds_ldap_auth_use_tls'), ('LDAP_AUTH_TLS_VERSION', 'lds_ldap_auth_tls_version'), ('LDAP_AUTH_SEARCH_BASE', 'lds_ldap_auth_search_base'), ('LDAP_DNS_LEGACY', 'lds_ldap_dns_legacy'), ('LDAP_AUTH_OBJECT_CLASS', 'lds_ldap_auth_object_class'), ('EXCLUDE_COMPUTER_ACCOUNTS', 'lds_exclude_computer_accounts'), ('LDAP_AUTH_USER_FIELDS', 'lds_ldap_auth_user_fields'), ('LDAP_DIRTREE_OU_FILTER', 'lds_ldap_dirtree_ou_filter'), ('LDAP_DIRTREE_CN_FILTER', 'lds_ldap_dirtree_cn_filter'), ('LDAP_AUTH_ACTIVE_DIRECTORY_DOMAIN', 'lds_ldap_auth_active_directory_domain'), ('LDAP_AUTH_CONNECTION_USER_DN', 'lds_ldap_auth_connection_user_dn'), ('LDAP_AUTH_CONNECTION_USERNAME', 'lds_ldap_auth_connection_username'), ('LDAP_AUTH_CONNECTION_PASSWORD', 'lds_ldap_auth_connection_password'), ('LDAP_AUTH_CONNECT_TIMEOUT', 'lds_ldap_auth_connect_timeout'), ('LDAP_AUTH_RECEIVE_TIMEOUT', 'lds_ldap_auth_receive_timeout'), ('ADMIN_GROUP_TO_SEARCH', 'lds_admin_group_to_search')], max_length=128, unique=True, verbose_name='name'),
        ),
    ]