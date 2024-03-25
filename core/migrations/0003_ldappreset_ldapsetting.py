# Generated by Django 4.2.4 on 2024-03-25 20:01

import core.models.validators.ldap_uri
import django.contrib.postgres.fields
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0002_user_recovery_codes'),
    ]

    operations = [
        migrations.CreateModel(
            name='LDAPPreset',
            fields=[
                ('created_at', models.DateTimeField(auto_now_add=True, verbose_name='created at')),
                ('modified_at', models.DateTimeField(auto_now=True, verbose_name='modified at')),
                ('deleted_at', models.DateTimeField(blank=True, null=True, verbose_name='deleted at')),
                ('deleted', models.BooleanField(default=False, verbose_name='deleted')),
                ('notes', models.TextField(blank=True, null=True)),
                ('id', models.BigAutoField(primary_key=True, serialize=False, verbose_name='id')),
                ('name', models.CharField(max_length=128, unique=True, verbose_name='name')),
            ],
            options={
                'abstract': False,
            },
        ),
        migrations.CreateModel(
            name='LDAPSetting',
            fields=[
                ('created_at', models.DateTimeField(auto_now_add=True, verbose_name='created at')),
                ('modified_at', models.DateTimeField(auto_now=True, verbose_name='modified at')),
                ('deleted_at', models.DateTimeField(blank=True, null=True, verbose_name='deleted at')),
                ('deleted', models.BooleanField(default=False, verbose_name='deleted')),
                ('notes', models.TextField(blank=True, null=True)),
                ('id', models.BigAutoField(primary_key=True, serialize=False, verbose_name='id')),
                ('name', models.CharField(max_length=128, unique=True, verbose_name='name')),
                ('type', models.CharField(choices=[('STRING', 'String'), ('BOOL', 'Boolean'), ('JSON', 'JSON Object'), ('PASSWORD', 'Password'), ('INTEGER', 'Integer'), ('LDAP_URI', 'LDAP URI')], verbose_name='type')),
                ('v_string', models.CharField(max_length=128, null=True, verbose_name='param_v_string')),
                ('v_password', models.CharField(null=True, verbose_name='param_v_password')),
                ('v_bool', models.BooleanField(null=True, verbose_name='param_v_bool')),
                ('v_json', models.JSONField(null=True, verbose_name='param_v_json')),
                ('v_integer', models.IntegerField(null=True, verbose_name='param_v_integer')),
                ('v_tls', models.CharField(null=True, verbose_name='param_v_tls')),
                ('v_ldap_uri', django.contrib.postgres.fields.ArrayField(base_field=models.CharField(max_length=255, verbose_name='param_v_ldap_uri'), null=True, size=None, validators=[core.models.validators.ldap_uri.validate_ldap_uri], verbose_name='param_v_ldap_uri_list')),
                ('preset', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='core.ldappreset', verbose_name='ldap_preset')),
            ],
            options={
                'abstract': False,
            },
        ),
    ]
