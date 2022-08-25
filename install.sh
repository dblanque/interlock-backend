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
err_req_install=1
err_yarn_pubkey=2
err_yarn_repo=3
err_yarn_install=4
err_mkdir_interlock=5
err_back_git_clone=10
err_back_pwdReplace=11
err_back_schemaGen=12
err_back_schemaInstall=13
err_back_venv_create=20
err_back_venv_activate=21
err_back_venv_reqs=22
err_back_service_copy=23
err_back_service_modify=24
err_back_migrate=30
err_back_create_superuser=31
err_back_venv_deactivate=32
err_back_service=33
err_front_yarn_install=40
err_front_yarn_build=41

workpath="/var/lib/interlock"
backendPath="$workpath/interlock_backend"
frontendPath="$workpath/interlock_frontend"

apt update -y
# Checks if update was successful.
if [ $? -ne 0 ]; then
    echo -e "${LIGHTRED}Could not update apt metadata, please check your connectivity or source.list entries${NC}"
    exit 1
fi

echo -e "${LIGHTBLUE}Testing gitlab connectivity.${NC}"
nc -z -v -w5 gitlab.brconsulting.info 22

# Checks if gitlab connectivity works.
if [ $? -ne 0 ]; then
    echo -e "${LIGHTRED}Could not connect to gitlab.brconsulting.info${NC}"
    exit 1
fi

ADDRESSES=(
    "gitlab.brconsulting.info"
)

for address in $ADDRESSES; do
    ssh-keygen -F $address 2>/dev/null 1>/dev/null
    if [ $? -eq 0 ]; then
        echo "SSH Key for $address is already known"
        continue
    fi
    ssh-keyscan -t rsa -T 10 $address >> ~/.ssh/known_hosts
done

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
libpq-dev
postgresql
nodejs
curl
nginx
)

toInstall=()

if [ "$EUID" != 0 ]; then
    sudo "$0" "$@"
    exit $?
fi

for r in "${reqs[@]}"
do
    apt -qq list $r 2>/dev/null|grep installed 1> /dev/null

    # Checks if requirements are met and tries to install.
    if [ $? -ne 0 ]; then
        echo -e "${LIGHTBLUE}$r is not installed, added to install array.${NC}"
        toInstall+=("$r")
    fi
done

toInstall_str=$(printf "%s " "${toInstall[@]}")

echo -e "${LIGHTBLUE}The following requirements will be installed:${NC}"
printf "\t%s\n" "${toInstall[@]}"

apt-get install $toInstall_str 2>/dev/null

# Checks if install was successful.
if [ $? != 0 ] && [ $? != 1 ]; then
    echo -e "${LIGHTRED}There was an error installing the requirements, installation cancelled.${NC}"
    echo "APT Exit Code: $?"
    exit $err_req_install
fi

# Checks if install was aborted.
if [ $? == 1 ]; then
    echo -e "${LIGHTBLUE}Interlock cannot be installed without these requirements.${NC}"
    echo "APT Exit Code: $?"
    exit $err_req_install
fi

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

apt update -y
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

if [[ ! -d "$workpath/sslcerts" ]]; then
    echo -e "${LIGHTRED}$workpath ${NC}directory does not exist, creating it."
    mkdir -p "$workpath/sslcerts"
    # Checks if curl repo add command was successful
    if [ $? -ne 0 ]; then
        echo -e "${LIGHTRED}Could not create Interlock SSL Certs Directory.${NC}"
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

if [[ ! -d $backendPath ]]; then
    git clone interlock-be:dblanque/interlock-backend $backendPath || throw $err_back_git_clone
else
    cd $backendPath
    git pull || throw $err_back_git_clone
fi

cd $backendPath

db_pwd="$(tr -dc A-Za-z0-9 </dev/urandom | head -c 13 ; echo '')"

# Replace Password in Local DB Settings File
sed -i "s/'PASSWORD':.*/'PASSWORD':'$db_pwd',/g" "$backendPath/interlock_backend/local_django_settings.py" || throw $err_back_pwdReplace

# Create and import initial schema to DB
# TODO - Add 
echo "-- Interlock PGSQL Create DB File
DROP DATABASE interlockdb;
DROP USER interlockadmin;
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
echo -e "${LIGHTBLUE}-------------------------------------------------------------------------------------------------------${NC}"
echo -e "If you wish to use SSL modify the backend service file at ${LIGHTBLUE}/etc/systemd/system/interlock_backend.service${NC}"
echo -e "${LIGHTBLUE}-------------------------------------------------------------------------------------------------------${NC}"
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
        $err_back_venv_deactivate)
            echo -e "${LIGHTRED}There was an error deactivating the virtual environment${NC}"
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
# Deactivate VENV
deactivate 2>/dev/null
# ! -- End of Stage 2 -- ! #

# Create SSL Certificate
sudo openssl req -x509 -nodes -days 36500 -newkey rsa:2048 -keyout "$workpath/sslcerts/privkey.pem" -out "$workpath/sslcerts/fullchain.pem"

# Checks if SSL Generation was successful.
if [ $? -ne 0 ]; then
    echo -e "${LIGHTRED}There was an error generating the SSL Certificate, please generate your certificate manually.${NC}"
    echo -e "\t- $workpath/sslcerts/privkey.pem"
    echo -e "\t- $workpath/sslcerts/fullchain.pem"
fi

# ! -- Beginning of Stage 3 -- ! #
try
(
source "$backendPath/bin/activate" || throw $err_back_venv_activate

# Apply migrations
"$backendPath/bin/python3" "$backendPath/manage.py" migrate || throw $err_back_migrate

# Creates default superuser
"$backendPath/bin/python3" "$backendPath/manage.py" shell < "$backendPath/install/create_default_superuser.py" || throw $err_back_create_superuser

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
        $err_back_venv_activate)
            echo -e "${LIGHTRED}Could not activate Virtual Environment${NC}"
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
# Deactivate VENV
deactivate 2>/dev/null
# ! -- End of Stage 3 -- ! #

# Go back to workpath
cd $workpath

##############################################
##############################################
########### FRONT-END INSTALLATION ###########
##############################################
##############################################
if [[ ! -d $frontendPath ]]; then
    git clone interlock-fe:dblanque/interlock-frontend $frontendPath
else
    cd $frontendPath
    git pull
fi

cd $frontendPath

try
(
yarn install || throw $err_front_yarn_install

yarn build || throw $err_front_yarn_build
)
catch || {
    # now you can handle
    case $ex_code in
        $err_front_yarn_install)
            echo -e "${LIGHTRED}There was an error installing the required components for the VueJS Front-end${NC}"
            throw $ex_code
        ;;
        $err_front_yarn_build)
            echo -e "${LIGHTRED}There was an error compiling the front end${NC}"
            throw $ex_code
        ;;
        *)
            echo "An unexpected exception was thrown"
            throw $ex_code # you can rethrow the "exception" causing the script to exit if not caught
        ;;
    esac
}

if [ test -e "/etc/nginx/sites-enabled/default" ]; then
    rm "/etc/nginx/sites-enabled/default"
fi

echo \
"server {
        listen 80;
        server_name default_server;
        return 301 https://\$host\$request_uri;
}

server {
    listen 443 ssl http2;
    server_name default_server;
    ssl_certificate $workpath/sslcerts/cert.pem;
    ssl_certificate_key $workpath/sslcerts/privkey.pem;

    add_header Allow \"GET, POST, HEAD, PUT, DELETE\" always;
    add_header Cache-Control no-cache;
    if (\$request_method !~ ^(GET|POST|HEAD|PUT|DELETE)$) {
        return 405;
    }

    location / {
        root $frontendPath/dist;
    }
}" > "/etc/nginx/sites-available/interlock"

# Checks if curl repo add command was successful
if [ $? -ne 0 ]; then
    echo -e "${LIGHTRED}Error creating Front-end NGINX Site.${NC}"
    echo -e "${LIGHTRED}A copy of the site file has been saved in $workpath${NC}"
echo \
"server {
        listen 80;
        server_name default_server;
        return 301 https://\$host\$request_uri;
}

server {
    listen 443 ssl http2;
    server_name default_server;
    ssl_certificate $workpath/sslcerts/cert.pem;
    ssl_certificate_key $workpath/sslcerts/privkey.pem;

    add_header Allow \"GET, POST, HEAD, PUT, DELETE\" always;
    add_header Cache-Control no-cache;
    if (\$request_method !~ ^(GET|POST|HEAD|PUT|DELETE)$) {
        return 405;
    }

    location / {
        root $frontendPath/dist;
    }
}" > "$workpath/interlock-nginx.conf"
fi

ln -s "/etc/nginx/sites-available/interlock" "/etc/nginx/sites-enabled/interlock"

systemctl enable nginx

# Advise Administrator to change the SSL Cert
echo -e "${LIGHTBLUE}-------------------------------------------------------------------------------------------------------${NC}"
echo -e "Don't forget to add your full chain and private key .pem files to ${LIGHTBLUE}$workpath/sslcerts/${NC}"
echo -e "\t- fullchain.pem"
echo -e "\t- privkey.pem"
echo
echo -e "To run SSL on the Back-end modify the systemd service file at ${LIGHTBLUE}/etc/systemd/system/interlock_backend.service${NC}"
echo -e "${LIGHTBLUE}-------------------------------------------------------------------------------------------------------${NC}"

echo "Interlock requires the following ports open on this server:"
echo -e "\t- 80 (HTTP)"
echo -e "\t- 443 (HTTPS)"
echo -e "\t- 8008 (Django Backend)"
echo
echo "Do not forget to open the LDAP port on your LDAP/AD Server(s):"
echo -e "\t- 389 (Default LDAP)"
echo -e "\t- 636 (Default LDAPS)"

exit