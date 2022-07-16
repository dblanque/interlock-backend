# Interlock Back-end Installation

1. Install the following dependencies
```bash
apt-get install git python3 python3-venv python3-pip postgresql
```

2. Once you’ve installed all the requirements, you can pull the latest repo.

```bash
git clone https://gitlab.brconsulting.info/dblanque/interlock-backend.git
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
        'NAME': 'syndb',
        'USER': 'synadmin',
        'PASSWORD': 'password',
        'HOST': '127.0.0.1',  # Or an IP Address that your DB is hosted on
        'PORT': '5432',
    }
}

logging_file_path = \"/var/log/interlock/backend.log\"

CORS_ALLOWED_ORIGINS = [
    \"http://localhost:8080\",
    \"https://localhost:8080\",
]
CSRF_TRUSTED_ORIGINS = [
    \"http://localhost:8080\",
    \"https://localhost:8080\",
]
" >> /opt/interlock-backend/interlock_backend/local_settings.py
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
cd /opt/interlock-backend/
virtualenv -p python3 .
source bin/activate
pip3 install -r requirements.txt
python3 ./manage.py migrate
python3 ./manage.py createsuperuser
```
