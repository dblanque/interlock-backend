#!/bin/bash
#CHECKS IF SCRIPT IS EXECUTED WITH BASH
if [ ! "$BASH_VERSION" ]; then
	echo "Please use bash to run this script." 1>&2
	exit 1
fi

LIGHTRED='\033[1;31m'
LIGHTGREEN='\033[1;32m'
LIGHTYELL='\033[1;33m'
LIGHTBLUE='\033[1;34m'
NC='\033[0m' # No Color

function try()
{
    [[ $- = *e* ]]; SAVED_OPT_E=$?
    set +e
}

function throw()
{
    exit $1
}

function catch()
{
    export ex_code=$?
    (( $SAVED_OPT_E )) && set +e
    return $ex_code
}

function throwErrors()
{
    set -e
}

function ignoreErrors()
{
    set +e
}

## Errors
$err_git_clone = 10


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
nginx
)

if [ "$EUID" != 0 ]; then
    sudo "$0" "$@"
    exit $?
fi

for r in "${reqs[@]}"
do
    apt -qq list $r 2>/dev/null|grep installed 1> /dev/null
    
    # Checks if requirements are met and tries to install.
    if [ $? -ne 0 ] ; then
        echo "$r is not installed, attempting to install requirement."
        apt-get -qq install $r -y 2>/dev/null
    fi
  
    # Checks if install was successful.
    if [ $? -ne 0 ]; then
        echo -e "${LIGHTRED}There was an error installing requirement $r, installation cancelled.${NC}"
        exit 1
    fi
done

curl -sS https://dl.yarnpkg.com/debian/pubkey.gpg | sudo apt-key add -

# Checks if the yarnpkg pubkey add command was successful
if [ $? -ne 0 ]; then
    echo -e "${LIGHTRED}Could not fetch Yarn Repository Pubkey.${NC}"
    echo "To do so manually you may execute the following command:"
    echo -e "\tcurl -sS https://dl.yarnpkg.com/debian/pubkey.gpg | sudo apt-key add -"
    exit 2
fi

echo "deb https://dl.yarnpkg.com/debian/ stable main" | sudo tee /etc/apt/sources.list.d/yarn.list

# Checks if curl repo add command was successful
if [ $? -ne 0 ] ; then
    echo -e "${LIGHTRED}Could not add Yarn repository.${NC}"
    echo "To do so manually you may execute the following command:"
    echo -e "\techo "deb https://dl.yarnpkg.com/debian/ stable main" | sudo tee /etc/apt/sources.list.d/yarn.list"
    exit 3
fi

apt-get -qq install yarn -y 2>/dev/null

# Checks if YARN install was successful.
if [ $? -ne 0 ]; then
    echo -e "${LIGHTRED}There was an error installing YARN, installation cancelled.${NC}"
    exit 4
fi

if [[ ! -d "/opt/interlock" ]]; then
    echo -e "${LIGHTRED}/opt/interlock ${NC}directory does not exist, creating it."
    mkdir -p "/opt/interlock"
    # Checks if curl repo add command was successful
    if [ $? -ne 0 ] ; then
        echo -e "${LIGHTRED}Could not create Interlock Installation Directory.${NC}"
        exit 5
    fi
fi

workpath="/opt/interlock"
backendPath="$workpath/interlock_backend"
frontendPath="$workpath/interlock_frontend"

cd "$workpath" || ( echo "Could not cd to directory /opt/interlock" && exit 1 )

##############################################
##############################################
############ BACK-END INSTALLATION ###########
##############################################
##############################################

# ! -- Beginning of Stage 1 -- ! #
try
(
# Clone repository
git clone gitbr:dblanque/interlock-backend || throw $err_git_clone

cd $backendPath

db_pwd="$(tr -dc A-Za-z0-9 </dev/urandom | head -c 13 ; echo '')"

# Replace Password in Local DB Settings File
sed -i "s/'PASSWORD':.*/'PASSWORD':'$db_pwd'/g" "$backendPath/interlock_backend/local_django_settings.py"

# Create and import initial schema to DB
echo "-- Interlock PGSQL Create DB File
CREATE DATABASE interlockdb;
CREATE USER interlockadmin WITH ENCRYPTED PASSWORD '$db_pwd';
GRANT ALL PRIVILEGES ON DATABASE interlockdb TO interlockadmin;" > "$backendPath/install/initial_schema.sql"

sudo -u postgres psql < "$backendPath/install/initial_schema.sql"
)
catch || {
    # now you can handle
    case $ex_code in
        *)
            echo "An unexpected exception was thrown"
            throw $ex_code # you can rethrow the "exception" causing the script to exit if not caught
        ;;
    esac
}
# ! -- End of Stage 1 -- ! #

# ! -- Beginning of Stage 2 -- ! #
# Do VENV Creation and install pip requirements
virtualenv -p python3 "$backendPath"
source "$backendPath/bin/activate"
pip3 install -r "$backendPath/requirements.txt"

# Create Systemd Service and copy it
cp "$backendPath/install/interlock_backend.service" "/etc/systemd/system/"
sed -i "s/User=.*/User=$(whoami)/g" "/etc/systemd/system/interlock_backend.service"
systemctl daemon-reload

# Advise Administrator to change the SSL Cert
echo -e "If you wish to use SSL modify the backend service file at ${LIGHTBLUE}/etc/systemd/system/interlock_backend.service${NC}"
# ! -- End of Stage 2 -- ! #

# ! -- Beginning of Stage 3 -- ! #
# Apply migrations
python3 "$backendPath/manage.py" migrate

# Creates default superuser
python3 "$backendPath/manage.py" shell < "$backendPath/install/create_default_superuser.py"

# Deactivate VENV
deactivate

systemctl enable interlock_backend && systemctl start interlock_backend
# ! -- End of Stage 3 -- ! #

# Go back to workpath
cd $workpath

##############################################
##############################################
########### FRONT-END INSTALLATION ###########
##############################################
##############################################
git clone gitbr:dblanque/interlock-frontend

cd $frontendPath

yarn install

yarn build

exit