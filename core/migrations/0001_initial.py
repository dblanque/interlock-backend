# Generated by Django 3.2 on 2022-08-26 15:39

import core.models.user
from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('auth', '0012_alter_user_first_name_max_length'),
    ]

    operations = [
        migrations.CreateModel(
            name='User',
            fields=[
                ('created_at', models.DateTimeField(auto_now_add=True, verbose_name='created at')),
                ('modified_at', models.DateTimeField(auto_now=True, verbose_name='modified at')),
                ('deleted_at', models.DateTimeField(blank=True, null=True, verbose_name='deleted at')),
                ('deleted', models.BooleanField(default=False, verbose_name='deleted')),
                ('notes', models.TextField(blank=True, null=True)),
                ('id', models.BigAutoField(primary_key=True, serialize=False)),
                ('username', models.CharField(max_length=128, unique=True, verbose_name='username')),
                ('password', models.CharField(max_length=128, verbose_name='password')),
                ('encryptedPassword', models.CharField(max_length=256, null=True, verbose_name='encryptedPassword')),
                ('last_login', models.DateTimeField(blank=True, null=True, verbose_name='last login')),
                ('is_staff', models.BooleanField(default=False, help_text='Designates whether the user is staff.', verbose_name='staff status')),
                ('is_superuser', models.BooleanField(default=False, help_text='Designates whether the user can log into this admin site and has superadmin privileges.', verbose_name='admin status')),
                ('first_name', models.CharField(blank=True, max_length=255, null=True, verbose_name='First name')),
                ('last_name', models.CharField(blank=True, max_length=255, null=True, verbose_name='Last name')),
                ('email', models.EmailField(blank=True, max_length=254, null=True, verbose_name='Email')),
                ('dn', models.CharField(blank=True, max_length=128, null=True, verbose_name='distinguishedName')),
                ('is_local', models.BooleanField(default=True)),
                ('groups', models.ManyToManyField(blank=True, help_text='The groups this user belongs to. A user will get all permissions granted to each of their groups.', related_name='user_set', related_query_name='user', to='auth.Group', verbose_name='groups')),
                ('user_permissions', models.ManyToManyField(blank=True, help_text='Specific permissions for this user.', related_name='user_set', related_query_name='user', to='auth.Permission', verbose_name='user permissions')),
            ],
            options={
                'verbose_name': 'User',
                'verbose_name_plural': 'Users',
            },
            managers=[
                ('objects', core.models.user.BaseUserManager()),
            ],
        ),
        migrations.CreateModel(
            name='Log',
            fields=[
                ('logged_at', models.DateTimeField(auto_now_add=True, verbose_name='logged at')),
                ('rotated', models.BooleanField(default=False, verbose_name='rotated')),
                ('notes', models.TextField(blank=True, null=True)),
                ('id', models.BigIntegerField(primary_key=True, serialize=False)),
                ('actionType', models.CharField(choices=[('CREATE', 'Create'), ('READ', 'Read'), ('UPDATE', 'Update'), ('DELETE', 'Delete'), ('LOGIN', 'Login'), ('LOGOUT', 'Logout'), ('OPEN', 'Open'), ('CLOSE', 'Close')], max_length=256, verbose_name='actionType')),
                ('objectClass', models.CharField(choices=[('USER', 'User'), ('GROUP', 'Group'), ('OU', 'Organizational Unit'), ('DOM', 'Domain'), ('GPO', 'Group Policy Object'), ('LDAP', 'LDAP Object'), ('CONN', 'Connection'), ('SET', 'Setting'), ('DNSZ', 'DNS Zone'), ('DNSR', 'DNS Record')], max_length=256, verbose_name='objectClass')),
                ('affectedObject', models.JSONField(blank=True, null=True, verbose_name='affectedObject')),
                ('extraMessage', models.CharField(blank=True, max_length=256, null=True, verbose_name='extraMessage')),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'abstract': False,
            },
        ),
    ]
