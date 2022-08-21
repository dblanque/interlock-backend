#!/bin/bash

LIGHTRED='\033[1;31m'
LIGHTGREEN='\033[1;32m'
LIGHTYELL='\033[1;33m'
LIGHTBLUE='\033[1;34m'
NC='\033[0m' # No Color

##############################################
##############################################
############# CHECK REQUIREMENTS #############
##############################################
##############################################

reqs=(
git
python3
python3-virtualenv
python3-venv
python3-pip
postgresql
nodejs
curl
)

for r in "${reqs[@]}"
do
    apt -qq list $r 2>/dev/null|grep installed 1> /dev/null
    
    # Checks if requirements are met and tries to install.
    if [ $? -ne 0 ] ; then
        echo "$r is not installed, attempting to install requirement."
        apt-get -qq install $r -y 2>/dev/null
    fi
  
    # Checks if install was successful.
    if [ $? -ne 0 ] ; then
        echo -e "${LIGHTRED}There was an error installing requirement $r, installation cancelled.${NC}"
        exit 1
    fi
done

curl -sS https://dl.yarnpkg.com/debian/pubkey.gpg | sudo apt-key add -

# Checks if the yarnpkg pubkey add command was successful
if [ $? -ne 0 ] ; then
    echo -e "${LIGHTRED}Could not fetch Yarn Repository Pubkey.${NC}"
    echo "To do so manually you may execute the following command:"
    echo -e "\tcurl -sS https://dl.yarnpkg.com/debian/pubkey.gpg | sudo apt-key add -"
    exit 1
fi

echo "deb https://dl.yarnpkg.com/debian/ stable main" | sudo tee /etc/apt/sources.list.d/yarn.list

# Checks if curl repo add command was successful
if [ $? -ne 0 ] ; then
    echo -e "${LIGHTRED}Could not add Yarn repository.${NC}"
    echo "To do so manually you may execute the following command:"
    echo -e "\techo "deb https://dl.yarnpkg.com/debian/ stable main" | sudo tee /etc/apt/sources.list.d/yarn.list"
    exit 1
fi

if [[ ! -d "/opt/interlock" ]]; then
    echo -e "${LIGHTRED}/opt/interlock ${NC}directory does not exist, creating it."
    mkdir -p "/opt/interlock"
    # Checks if curl repo add command was successful
    if [ $? -ne 0 ] ; then
        echo -e "${LIGHTRED}Could not create Interlock Directory.${NC}"
        exit 1
    fi
fi

workpath="/opt/interlock"

cd "$workpath" || ( echo "Could not cd to directory /opt/interlock" && exit 1 )

### ! BACK-END INSTALLATION ###
# Clone repository
git clone gitbr:dblanque/interlock-backend

# Replace Password in Local DB Settings File
sed -i "s/'PASSWORD':.*/'PASSWORD':'$db_pwd'/g" "$workpath/interlock_backend/local_django_settings.py"

db_pwd="$(tr -dc A-Za-z0-9 </dev/urandom | head -c 13 ; echo '')"

# Create and import initial schema to DB
echo "-- Interlock PGSQL Create DB File
CREATE DATABASE interlockdb;
CREATE USER interlockadmin WITH ENCRYPTED PASSWORD '$db_pwd';
GRANT ALL PRIVILEGES ON DATABASE interlockdb TO interlockadmin;" > "$workpath/install/initial_schema.sql"

sudo -u postgres psql < "$workpath/install/initial_schema.sql"

# Checks if PSQL Command was Successful
if [ $? -ne 0 ] ; then
    echo -e "${LIGHTRED}Could not create Interlock DB or User.${NC}"
    exit 4
ficreate_default_superuser.py

# Do VENV Creation and install pip requirements
virtualenv -p python3 "$workpath"
source "$workpath/bin/activate"
pip3 install -r "$workpath/requirements.txt"

# Create Systemd Service
# TODO - Change user in service automatically, tell installer user to add certs to sslcerts folder
cp "$workpath/install/interlock_backend.service" "/etc/systemd/system/"
systemctl daemon-reload

# Creates default superuser
python3 "$workpath/manage.py" shell < "$workpath/install/create_default_superuser.py"
# echo "from django.contrib.auth import get_user_model; User = get_user_model(); User.objects.create_default_superuser()" | python manage.py shell

### ! FRONT-END INSTALLATION ###
git clone gitbr:dblanque/interlock-frontend