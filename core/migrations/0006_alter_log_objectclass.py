# Generated by Django 3.2 on 2022-07-31 05:10

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0005_auto_20220731_0315'),
    ]

    operations = [
        migrations.AlterField(
            model_name='log',
            name='objectClass',
            field=models.CharField(choices=[('USER', 'User'), ('GROUP', 'Group'), ('OU', 'Organizational Unit'), ('DOM', 'Domain'), ('GPO', 'Group Policy Object'), ('LDAP', 'LDAP Object'), ('CONN', 'Connection'), ('SET', 'Setting')], max_length=256, verbose_name='objectClass'),
        ),
    ]