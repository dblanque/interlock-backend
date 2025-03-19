# Interlock Documentation

[Interlock Website](https://interlock.brconsulting.info/)

For information and official Interlock Documentation go to:
[BR Consulting S.R.L. Documentation - Interlock](https://docs.brconsulting.info/sphinx/en/docs/Development/Interlock/00-ilck-overview.html)

### Would you like to support me?
<a href='https://ko-fi.com/E1E2YQ4TG' target='_blank'><img height='36' style='border:0px;height:36px;' src='https://storage.ko-fi.com/cdn/kofi2.png?v=3' border='0' alt='Buy Me a Coffee at ko-fi.com' /></a>

# Installation from Source

1. Install the following dependencies
```bash
apt-get install git python3 python3-venv python3-pip postgresql
```

2. Once you’ve installed all the requirements, you can pull the latest repo.

```bash
git clone https://github.com/dblanque/interlock-backend.git
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
}" >> /opt/interlock-backend/interlock_backend/local_settings.py
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
cd /opt/interlock-backend/
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
## (It will auto-create on first login if not done like this)
### With django script
python3 ./manage.py shell < install/create_default_superuser.py
### Manually
python3 ./manage.py createsuperuser

## Create RSA Encryption Key Pair for LDAP Connections 
## (It will auto-create on first login if not done like this)
python3 ./manage.py shell < install/create_rsa_key.py

## Create RSA Encryption Key Pair for OIDC
## (It will auto-create on first login if not done like this)
python manage.py creatersakey
```
# PROJECT LICENSE

*Interlock Copyright (C) 2022-2024 | Dylan Blanqué, BR Consulting S.R.L.*

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
