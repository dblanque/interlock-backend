# Interlock Documentation
[![Official Website](./reports/badges/website-badge.svg?dummy=12345678)](https://interlock.brconsulting.info)
[![Docs](./reports/badges/docs-badge.svg?dummy=12345678)](https://docs.brconsulting.info/en/docs/development/interlock/)
[![Django Version](./reports/badges/django-version-badge.svg?dummy=12345678)](./reports/badges/django-version-badge.svg)
[![Python Versions](./reports/badges/python-versions-badge.svg?dummy=12345678)](./reports/badges/python-versions-badge.svg)
[![Tests](./reports/badges/tests-badge.svg?dummy=12345678)](./reports/badges/tests-badge.svg)
[![Coverage Status](./reports/badges/coverage-badge.svg?dummy=12345678)](./reports/badges/coverage-badge.svg)

* Beware: If you have installed a version of Interlock <= 1.1.0 you will have
to re-install and re-configure the LDAP Back-end settings in your installation
due to major re-factors and package version changes.

# What is Interlock?

Interlock is an **Open-Source Project** powered by *VueJS/Vuetify* and
*Django Rest Framework* made for Organization Credentials and Authorization Management,
and can serve as an SSO Authorizer or Identity Provider (IdP).

[Click here to visit the official Website for Interlock](https://interlock.brconsulting.info/)

For information and official Interlock Documentation go to:
[BR Consulting S.R.L. Documentation - Interlock](https://docs.brconsulting.info/sphinx/en/docs/Development/Interlock/00-ilck-overview.html)

It also sports several bonus features such as being able to manage an LDAP
Server's *-or Server Pool's-* **DNS Zones**, **TOTP**,
**API-fying** LDAP Servers, and more.

It supports several main use-cases:
* Stand-alone (Credentials are saved in a local database)
	* User Management.
	* SSO Application Management.
	* SSO Application Groups Management.
	* Authentication with TOTP.
* LDAP Back-end
	* Samba LDAP Back-end.
	* Microsoft Active Directory Services Back-end.

Both LDAP Back-ends support the following features.
* All of the Stand-alone mode features.
* LDAP User CRUD, Group Membership, and Permissions Management.
* LDAP Group CRUD and Members Management.
* DNS Zones Management.
* Directory Tree Management
	* Organizational Units CRUD.
	* Moving LDAP Objects.
	* Renaming LDAP Objects.

### Would you like to support me?
<a href='https://ko-fi.com/E1E2YQ4TG' target='_blank'><img height='36' style='border:0px;height:36px;' src='https://storage.ko-fi.com/cdn/kofi2.png?v=3' border='0' alt='Buy Me a Coffee at ko-fi.com' /></a>

For official support feel free to contact us through either of these websites:
* <https://brconsulting.info/>
* <https://cloudship.net/>

# Installation from Source

1. Install the following dependencies
```bash
apt-get install git python3 python3-venv python3-pip postgresql
```

2. Once you’ve installed all the requirements, you can pull the latest repo.

```bash
mkdir -p /var/lib/interlock/
git clone https://github.com/dblanque/interlock-backend.git /var/lib/interlock/interlock_backend/
```

3. Add the basic schema to the database

* Use user Postgres in your shell and open PSQL
```bash
su postgres
psql
```

* Enter the following statements in Postgres
```sql
/* PSQL */
CREATE ROLE interlockadmin WITH PASSWORD 'Clave1234'; /* Change this password */
CREATE DATABASE interlockdb;
ALTER ROLE interlockadmin WITH LOGIN;
ALTER DATABASE interlockdb OWNER to interlockadmin;
```

4. Create your Local Settings file and setup basic Postgres Settings
```bash
# Put your version here, Postgres 11, 12, etc.
# Example: /etc/postgresql/12/(...)
version=
# SHELL CONSOLE
echo "# Database Administrative Login for interlockadmin user with MD5" >> /etc/postgresql/$version/main/pg_hba.conf
echo -e "local\tall\tinterlockadmin\tmd5" >> /etc/postgresql/$version/main/pg_hba.conf
unset $version

echo "
DATABASES = {
	\"default\": {
		'ENGINE': 'django.db.backends.postgresql',
		'NAME': 'interlockdb',
		'USER': 'interlockadmin',
		'PASSWORD': 'password',
		'HOST': '127.0.0.1',  # Or an IP Address that your DB is hosted on
		'PORT': '5432',
	}
}" >> /var/lib/interlock/interlock_backend/interlock_backend/local_settings.py
```

5. Create the Log Directory and file
```bash
mkdir /var/log/interlock/
touch /var/log/interlock/backend.log
chown -R $(whoami):$(whoami) /var/log/interlock
```

6. Installing the Python requirements
Now we must install the requirements in a virtual environment with pip.
**ALWAYS** run your virtualenv to avoid creating issues with your local python dependencies

```bash
# Create the Virtual Environment
cd /var/lib/interlock/interlock_backend/
python3 -m venv venv --upgrade

# Activate it and Install the Requirements
source venv/bin/activate
pip3 install poetry
poetry install

# Make migrations and apply them to DB
python3 ./manage.py makemigrations
python3 ./manage.py migrate
python3 ./manage.py creatersakey

# OPTIONAL
## Create Default Superuser
python3 ./manage.py shell < install/create_default_superuser.py

## Create RSA Encryption Key Pair for LDAP Connections 
python3 ./manage.py shell < install/create_rsa_key.py

## Create RSA Encryption Key Pair for OIDC
python manage.py creatersakey
```

# FAQ - Frequently Asked Questions

* Why does the repository not have any tags related to versioning?
> Even though we upload the same commits to both Github and our own Gitlab,
we control that internally in our private Gitlab repositories to avoid
redundancies and MR/PR conflicts.

* Will support for RPM using distros exist?
> Not planned at the moment, maybe if the project gains traction and support,
and demand for that specific case.

# PROJECT LICENSE

*Interlock Copyright (C) 2022-2025 | Dylan Blanqué, BR Consulting S.R.L.*

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://fsf.org/>.

This program comes with ABSOLUTELY NO WARRANTY.
