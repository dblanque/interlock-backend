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
err_req_install = 1
err_yarn_pubkey = 2
err_yarn_repo = 3
err_yarn_install = 4
err_mkdir_interlock = 5
err_back_git_clone = 10
err_back_pwdReplace = 11
err_back_schemaGen = 12
err_back_schemaInstall = 13
err_back_venv_create = 20
err_back_venv_activate = 21
err_back_venv_reqs = 22
err_back_service_copy = 23
err_back_service_modify = 24
err_back_migrate = 30
err_back_create_superuser = 31
err_back_venv_deactivate = 32
err_back_service = 33

workpath="/var/lib/interlock"
backendPath="$workpath/interlock_backend"
frontendPath="$workpath/interlock_frontend"

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
    if [ $? -ne 0 ]; then
        echo "$r is not installed, attempting to install requirement."
        apt-get -qq install $r -y 2>/dev/null
    fi
  
    # Checks if install was successful.
    if [ $? -ne 0 ]; then
        echo -e "${LIGHTRED}There was an error installing requirement $r, installation cancelled.${NC}"
        exit $err_req_install
    fi
done

curl -sS https://dl.yarnpkg.com/debian/pubkey.gpg | sudo apt-key add -

# Checks if the yarnpkg pubkey add command was successful
if [ $? -ne 0 ]; then
    echo -e "${LIGHTRED}Could not fetch Yarn Repository Pubkey.${NC}"
    echo "To do so manually you may execute the following command:"
    echo -e "\tcurl -sS https://dl.yarnpkg.com/debian/pubkey.gpg | sudo apt-key add -"
    exit $err_yarn_pubkey
fi

echo "deb https://dl.yarnpkg.com/debian/ stable main" | sudo tee /etc/apt/sources.list.d/yarn.list

# Checks if curl repo add command was successful
if [ $? -ne 0 ]; then
    echo -e "${LIGHTRED}Could not add Yarn repository.${NC}"
    echo "To do so manually you may execute the following command:"
    echo -e "\techo "deb https://dl.yarnpkg.com/debian/ stable main" | sudo tee /etc/apt/sources.list.d/yarn.list"
    exit $err_yarn_repo
fi

apt-get -qq install yarn -y 2>/dev/null

# Checks if YARN install was successful.
if [ $? -ne 0 ]; then
    echo -e "${LIGHTRED}There was an error installing YARN, installation cancelled.${NC}"
    exit $err_yarn_install
fi

if [[ ! -d $workpath ]]; then
    echo -e "${LIGHTRED}$workpath ${NC}directory does not exist, creating it."
    mkdir -p $workpath
    # Checks if curl repo add command was successful
    if [ $? -ne 0 ]; then
        echo -e "${LIGHTRED}Could not create Interlock Installation Directory.${NC}"
        exit $err_mkdir_interlock
    fi
fi

cd "$workpath" || ( echo "Could not cd to directory $workpath" && exit 1 )

##############################################
##############################################
############ BACK-END INSTALLATION ###########
##############################################
##############################################

# ! -- Beginning of Stage 1 -- ! #
try
(
# Clone repository
git clone interlock-be:dblanque/interlock-backend || throw $err_back_git_clone

cd $backendPath

db_pwd="$(tr -dc A-Za-z0-9 </dev/urandom | head -c 13 ; echo '')"

# Replace Password in Local DB Settings File
sed -i "s/'PASSWORD':.*/'PASSWORD':'$db_pwd'/g" "$backendPath/interlock_backend/local_django_settings.py" || throw $err_back_pwdReplace

# Create and import initial schema to DB
echo "-- Interlock PGSQL Create DB File
CREATE DATABASE interlockdb;
CREATE USER interlockadmin WITH ENCRYPTED PASSWORD '$db_pwd';
GRANT ALL PRIVILEGES ON DATABASE interlockdb TO interlockadmin;" > "$backendPath/install/initial_schema.sql" || throw $err_back_schemaGen

sudo -u postgres psql < "$backendPath/install/initial_schema.sql" || throw $err_back_schemaInstall
)
catch || {
    # now you can handle
    case $ex_code in
        $err_back_git_clone)
            echo "Unable to clone Interlock Backend"
            throw $ex_code # you can rethrow the "exception" causing the script to exit if not caught
        ;;
        $err_back_pwdReplace)
            echo "Could not apply automatic generated password to file $backendPath/interlock_backend/local_django_settings.py"
            throw $ex_code # you can rethrow the "exception" causing the script to exit if not caught
        ;;
        $err_back_schemaGen)
            echo "Could not generate Initial DB Schema"
            throw $ex_code # you can rethrow the "exception" causing the script to exit if not caught
        ;;
        $err_back_schemaInstall)
            echo "Could not apply Initial DB Schema"
            throw $ex_code # you can rethrow the "exception" causing the script to exit if not caught
        ;;
        *)
            echo "An unexpected exception was thrown"
            throw $ex_code # you can rethrow the "exception" causing the script to exit if not caught
        ;;
    esac
}
# ! -- End of Stage 1 -- ! #

# ! -- Beginning of Stage 2 -- ! #
try
(
# Do VENV Creation and install pip requirements
virtualenv -p python3 "$backendPath" || throw $err_back_venv_create
source "$backendPath/bin/activate" || throw $err_back_venv_activate
pip3 install -r "$backendPath/requirements.txt" || throw $err_back_venv_reqs

# Create Systemd Service and copy it
cp "$backendPath/install/interlock_backend.service" "/etc/systemd/system/" || throw $err_back_service_copy
sed -i "s/User=.*/User=$(whoami)/g" "/etc/systemd/system/interlock_backend.service" || throw $err_back_service_modify
systemctl daemon-reload

# Advise Administrator to change the SSL Cert
echo -e "If you wish to use SSL modify the backend service file at ${LIGHTBLUE}/etc/systemd/system/interlock_backend.service${NC}"
)
catch || {
    # now you can handle
    case $ex_code in
        $err_back_venv_create)
            echo -e "${LIGHTRED}Could not create Virtual Environment${NC}"
            throw $ex_code
        ;;
        $err_back_venv_activate)
            echo -e "${LIGHTRED}Could not activate Virtual Environment${NC}"
            throw $ex_code
        ;;
        $err_back_venv_reqs)
            echo -e "${LIGHTRED}Could not install requirements in Virtual Environment${NC}"
            throw $ex_code
        ;;
        $err_back_service_copy)
            echo -e "${LIGHTRED}Could not copy Interlock Backend Systemd Service Unit${NC}"
            throw $ex_code
        ;;
        $err_back_service_modify)
            echo -e "${LIGHTRED}Could not modify Interlock Backend Systemd Service Unit user${NC}"
            throw $ex_code
        ;;
        *)
            echo "An unexpected exception was thrown"
            throw $ex_code # you can rethrow the "exception" causing the script to exit if not caught
        ;;
    esac
}
# ! -- End of Stage 2 -- ! #

# ! -- Beginning of Stage 3 -- ! #
try
(
# Apply migrations
python3 "$backendPath/manage.py" migrate || throw $err_back_migrate

# Creates default superuser
python3 "$backendPath/manage.py" shell < "$backendPath/install/create_default_superuser.py" || throw $err_back_create_superuser

# Deactivate VENV
deactivate || throw $err_back_venv_deactivate

(systemctl enable interlock_backend && systemctl start interlock_backend) || throw $err_back_service
)
catch || {
    # now you can handle
    case $ex_code in
        $err_back_migrate)
            echo -e "${LIGHTRED}Could not apply Django Migrations${NC}"
            throw $ex_code
        ;;
        $err_back_create_superuser)
            echo -e "${LIGHTRED}Could not Create Default Superuser${NC}"
            throw $ex_code
        ;;
        $err_back_venv_deactivate)
            echo -e "${LIGHTRED}There was an error deactivating the virtual environment${NC}"
            throw $ex_code
        ;;
        $err_back_service)
            echo -e "${LIGHTRED}There was an error enabling or starting the Systemd Service${NC}"
            throw $ex_code
        ;;
        *)
            echo "An unexpected exception was thrown"
            throw $ex_code # you can rethrow the "exception" causing the script to exit if not caught
        ;;
    esac
}
# ! -- End of Stage 3 -- ! #

# Go back to workpath
cd $workpath

##############################################
##############################################
########### FRONT-END INSTALLATION ###########
##############################################
##############################################
git clone interlock-fe:dblanque/interlock-frontend

cd $frontendPath

yarn install

yarn build

echo "Front-end build was generated in $frontendPath/dist"

exit