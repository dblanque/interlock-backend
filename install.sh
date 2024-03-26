#!/bin/bash
#CHECKS IF SCRIPT IS EXECUTED WITH BASH
if [ ! "$BASH_VERSION" ]; then
	echo "Please use bash to run this script." 1>&2
	exit 1
fi

# Trap Exit Signal
trap "echo && exit" INT

LIGHTRED='\033[1;31m'
LIGHTGREEN='\033[1;32m'
LIGHTYELL='\033[1;33m'
LIGHTBLUE='\033[1;34m'
NC='\033[0m' # No Color

if [[ ! $scriptname ]]; then
    scriptname="`echo $BASH_SOURCE|awk -F "/" '{print $NF}'`"
fi

compileFront=false

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

valid_ip () {
    local  ip=$1
    local  stat=1

    if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        OIFS=$IFS
        IFS='.'
        ip=($ip)
        IFS=$OIFS
        [[ ${ip[0]} -le 255 && ${ip[1]} -le 255 && ${ip[2]} -le 255 && ${ip[3]} -le 255 ]]
        stat=$?
    fi
    echo $stat
    return $stat
}

## Errors
err_req_install=1
err_yarn_pubkey=2
err_yarn_repo=3
err_node_script=4
err_node_repo=5
err_yarnOrNode_install=6
err_mkdir_interlock=7
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
err_front_git_clone=40
err_front_yarn_install=41
err_front_yarn_build=42

workpath="/var/lib/interlock"
configPath="/etc/interlock"
backendPath="$workpath/interlock_backend"
frontendPath="$workpath/interlock_frontend"

# COPIES ALL ARGUMENTS TO ARRAY
argv_a=($@)

#GETS COMMAND ARGS
for i in "${!argv_a[@]}"; 
    do
        j=`expr $i + 1`

        case "${argv_a[i]}" in
            --help|--h|-h )
                echo "Script Options:"
                echo -e "\t --compile | Installs dependencies and recompiles the front-end source"
                exit
                ;;
            --compile|--c|-c )
                echo -e "${LIGHTBLUE}Compile flag detected${NC}"
                compileFront=true
                ;;
            * )
                echo "Invalid argument. (`echo ${i}`)"
                echo "Usage: $scriptname --option"
                exit
                ;;
        esac
    done

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

backendURL=""
domainPattern='(?=^.{4,253}$)(^(?:[a-zA-Z0-9](?:(?:[a-zA-Z0-9\-]){0,61}[a-zA-Z0-9])?(\.)?)+([a-zA-Z]{2,}|xn--[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])$)'

backendURL_valid=false
until [[ $backendURL_valid == true ]]; do
    read -rp "Please enter the back-end URL to be used (Must be a Valid TLD or IP, Single Label is allowed): " backendURL
    
    # Test if Backend URL is a valid IP or TLD
    backendIsIP=`valid_ip $backendURL`
    if [[ $backendIsIP != 0 ]] && [[ ! `echo $backendURL | grep -P $domainPattern` ]];
    then
        echo "Invalid Back-end URL"
        exit 190
    else
        backendURL_valid=true
    fi
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

# Create required Directory
if [[ ! -d "$workpath/sslcerts" ]]; then
    echo -e "${LIGHTRED}$workpath/sslcerts ${NC}directory does not exist, creating it."
    mkdir -p "$workpath/sslcerts"
    # Checks if curl repo add command was successful
    if [ $? -ne 0 ]; then
        echo -e "${LIGHTRED}Could not create Interlock Installation Directories.${NC}"
        exit $err_mkdir_interlock
    fi
fi

# Create required Config Directory
if [[ ! -d "$configPath" ]]; then
    echo -e "${LIGHTRED}$configPath ${NC}directory does not exist, creating it."
    mkdir -p "$configPath"
    # Checks if curl repo add command was successful
    if [ $? -ne 0 ]; then
        echo -e "${LIGHTRED}Could not create Interlock Config Directory.${NC}"
        exit $err_mkdir_interlock
    fi
fi

if [ $compileFront == true ]; then
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

    curl -sL https://deb.nodesource.com/setup_16.x -o "$workpath/nodesource_setup.sh"

    # Checks if the yarnpkg pubkey add command was successful
    if [ $? -ne 0 ]; then
        echo -e "${LIGHTRED}Could not fetch NodeJS Repository Install Script.${NC}"
        echo "To do so manually you may execute the following command:"
        echo -e "\tcurl -sL https://deb.nodesource.com/setup_16.x -o $workpath/nodesource_setup.sh"
        exit $err_node_script
    fi

    bash "$workpath/nodesource_setup.sh"

    # Checks if curl repo add command was successful
    if [ $? -ne 0 ]; then
        echo -e "${LIGHTRED}Could not add NodeJS Repository.${NC}"
        echo "To do so manually you may execute the following command:"
        echo -e "\tbash $workpath/nodesource_setup.sh"
        exit $err_node_repo
    fi

    apt update -y
    apt-get -qq install yarn nodejs -y 2>/dev/null

    # Checks if YARN and NodeJS installs were successful.
    if [ $? -ne 0 ]; then
        echo -e "${LIGHTRED}There was an error installing YARN and/or NodeJS, installation cancelled.${NC}"
        exit $err_yarnOrNode_install
    fi
fi

generateSSLCert=""
if [[ -f "$workpath/sslcerts/fullchain.pem" ]] && [[ -f "$workpath/sslcerts/privkey.pem" ]]; then
    until [[ $generateSSLCert == true ]] || [[ $generateSSLCert == false ]]; do
    read -n 1 -rp "Would you like to re-generate the SSL Certificate? (Y|N) [N]: " generateSSLCert
        case $generateSSLCert in
            [Yy] )
                generateSSLCert=true
            ;;
            * )
                generateSSLCert=false
            ;;
        esac
    done
fi

if [[ $generateSSLCert == true ]] || [[ ! -f "$workpath/sslcerts/fullchain.pem" ]] || [[ ! -f "$workpath/sslcerts/privkey.pem" ]]; then
    # Create SSL Certificate
    sudo openssl req -x509 -subj "/CN=$(hostname)/" -nodes -days 36500 -newkey rsa:2048 -keyout "$workpath/sslcerts/privkey.pem" -out "$workpath/sslcerts/fullchain.pem"
fi

# Checks if SSL Generation was successful.
if [ $? -ne 0 ] || [[ ! -f "$workpath/sslcerts/privkey.pem" ]] || [[ ! -f "$workpath/sslcerts/fullchain.pem" ]]; then
    echo -e "${LIGHTRED}There was an error generating the SSL Certificate. \nPlease generate your certificate manually in the following paths:${NC}"
    echo -e "\t- $workpath/sslcerts/privkey.pem"
    echo -e "\t- $workpath/sslcerts/fullchain.pem"
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
    git stash
    git pull || throw $err_back_git_clone
fi

cd $backendPath

if [ ! -f "$configPath/db_config.conf" ]; then
    db_pwd="$(tr -dc A-Za-z0-9 </dev/urandom | head -c 13 ; echo '')"
    touch "$configPath/db_config.conf"
    echo "db_pwd=\"$db_pwd\"" > "$configPath/db_config.conf"
else
    source "$configPath/db_config.conf"
fi

if [ ! -f "$configPath/django_settings.py" ]; then
    ln -s "$backendPath/interlock_backend/settings.py" "$configPath/django_settings.py"
fi

# Replace Password in Local DB Settings File
sed -i "s/'PASSWORD':.*/'PASSWORD':'$db_pwd',/g" "$backendPath/interlock_backend/local_django_settings.py" || throw $err_back_pwdReplace

keepDB=""
until [[ $keepDB == true ]] || [[ $keepDB == false ]]; do
read -n 1 -rp "Do you wish to preserve the Database if it exists? (Y|N) [N]: " keepDB
    case $keepDB in
        [Yy] )
            echo
            echo -e "${LIGHTYELL}Preserving Interlock Database${NC}."
            keepDB=true
        ;;
        * )
            echo
            echo -e "${LIGHTRED}Resetting Interlock Database${NC}."
            keepDB=false
        ;;
    esac
done


# Create and import initial schema to DB
if [[ $keepDB == true ]]; then
echo "-- Interlock PGSQL Create DB File

DO
\$do\$
BEGIN
   IF NOT EXISTS (SELECT * FROM pg_user WHERE usename = 'interlockadmin') THEN
        CREATE USER interlockadmin WITH ENCRYPTED PASSWORD '$db_pwd';
    ELSE
        ALTER USER interlockadmin WITH PASSWORD '$db_pwd';
   END IF;
END
\$do\$;

DO
\$do\$
BEGIN
   IF EXISTS (SELECT FROM pg_database WHERE datname = 'interlockdb') THEN
      RAISE NOTICE 'Database already exists';  -- optional
   ELSE
      PERFORM dblink_exec('dbname=' || current_database()  -- current db
                        , 'CREATE DATABASE interlockdb');
   END IF;
END
\$do\$;

GRANT ALL PRIVILEGES ON DATABASE interlockdb TO interlockadmin;" > "$backendPath/install/initial_schema.sql" || throw $err_back_schemaGen
else
echo "-- Interlock PGSQL Create DB File
DROP DATABASE interlockdb;
DROP USER interlockadmin;
CREATE DATABASE interlockdb;
CREATE USER interlockadmin WITH ENCRYPTED PASSWORD '$db_pwd';
GRANT ALL PRIVILEGES ON DATABASE interlockdb TO interlockadmin;" > "$backendPath/install/initial_schema.sql" || throw $err_back_schemaGen
fi

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

# ! -- Beginning of Stage 3 -- ! #
try
(
source "$backendPath/bin/activate" || throw $err_back_venv_activate

# Not necessary, we're not using basic CORS stuff
# sed -i "s/ALLOWED_HOSTS = \[.*/ALLOWED_HOSTS = ['$backendURL']/g" "$backendPath/interlock_backend/settings.py"

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
try
(
    if [[ ! -d $frontendPath ]]; then
        git clone interlock-fe:dblanque/interlock-frontend $frontendPath || throw $err_front_git_clone
    else
        cd $frontendPath
        rm -r "$frontendPath/dist"
        git stash
        git pull || throw $err_front_git_clone
    fi

    cd $frontendPath

    sed -i "s/const ssl.*/const ssl = true/g" "$frontendPath/src/providers/interlock_backend/config.js"
    sed -i "s/\"127.0.0.1:8000\"/\"$backendURL\"/g" $frontendPath/dist/js/app*.js
    sed -i "s/\"127.0.0.1:8000\"/\"$backendURL\"/g" $frontendPath/dist/js/app*.map.js
    sed -i "s/ssl:!1/ssl:!0/g" $frontendPath/dist/js/app*.js
    sed -i "s/ssl:!1/ssl:!0/g" $frontendPath/dist/js/app*.map.js
    sed -i "s/backend_url:.*/backend_url: \"${backendURL}\",/g" "$frontendPath/src/providers/interlock_backend/local_settings.js"
    
    if [ $compileFront == true ]; then
        yarn install || throw $err_front_yarn_install
        yarn build || throw $err_front_yarn_build
    fi
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

if [ -e "/etc/nginx/sites-enabled/default" ]; then
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
    ssl_certificate $workpath/sslcerts/fullchain.pem;
    ssl_certificate_key $workpath/sslcerts/privkey.pem;

    location / {
        root $frontendPath/dist;

        index index.html index.htm index.nginx-debian.html;
        try_files \$uri /index.html;

        # kill cache
        add_header Last-Modified \$date_gmt;
        # add_header Cache-Control 'no-store, no-cache';
        add_header Cache-Control 'max-age=900';
        if_modified_since off;
        expires off;
        etag off;
    }
}" > "$workpath/interlock.conf"

echo \
"server {
    listen 80;
    server_name $backendURL;
    return 301 https://$backendURL\$request_uri;
}

server {
    listen 443 ssl;
    server_name $backendURL;
    server_name_in_redirect off;
    access_log  /var/log/nginx/access.log;
    error_log  /var/log/nginx/error.log debug;

    ssl_certificate $workpath/sslcerts/fullchain.pem;
    ssl_certificate_key $workpath/sslcerts/privkey.pem;

    add_header Allow \"GET, POST, HEAD, PUT, DELETE, OPTIONS\" always;
    add_header Cache-Control no-cache;
    if (\$request_method !~ ^(GET|POST|HEAD|PUT|DELETE|OPTIONS)\$) {
        return 405;
    }

    location / {
        proxy_pass https://127.0.0.1:8000;
        proxy_set_header Host \$host;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}" > "$workpath/interlock-backend.conf"

cp "$workpath/interlock.conf" "/etc/nginx/sites-available/interlock"
cp "$workpath/interlock-backend.conf" "/etc/nginx/sites-available/interlock-backend"

# Checks if curl repo add command was successful
if [ $? -ne 0 ]; then
    echo -e "${LIGHTRED}Error creating Front-end NGINX Site.${NC}"
    echo -e "${LIGHTRED}A copy of the site file has been saved in $workpath${NC}"
fi

ln -s "/etc/nginx/sites-available/interlock" "/etc/nginx/sites-enabled/"
ln -s "/etc/nginx/sites-available/interlock-backend" "/etc/nginx/sites-enabled/"

systemctl enable nginx
systemctl restart nginx

# Advise Administrator to change the SSL Cert
echo -e "${LIGHTBLUE}-------------------------------------------------------------------------------------------------------${NC}"
echo -e "If you have a Valid signed SSL Certificate, don't forget to add your full chain and private key .pem files to ${LIGHTBLUE}$workpath/sslcerts/${NC}"
echo -e "\t- fullchain.pem"
echo -e "\t- privkey.pem"
echo
echo -e "${LIGHTYELLOW}To run the backend without SSL${NC} modify the systemd service file at ${LIGHTBLUE}/etc/systemd/system/interlock_backend.service${NC}"
echo -e "That will require you to also disable ssl on ${LIGHTBLUE}$frontendPath/src/providers/interlock_backend/config.js${NC}"
echo -e "And re-build the front-end with the following command: ${LIGHTBLUE}cd $frontendPath && yarn build${NC}"
echo -e "${LIGHTBLUE}-------------------------------------------------------------------------------------------------------${NC}"

echo "Interlock requires the following ports open on this server:"
echo -e "\t- 80 (HTTP)"
echo -e "\t- 443 (HTTPS)"
# echo -e "\t- 8000 (Django Backend)"
echo
echo "Please add the following entries to your Internal DNS:"
echo -e "\t- $backendURL"
echo -e "\t- Whatever URL you wish the Front-end to be in"
echo "To add an entry through CLI on your Samba AD do:"
echo -e "\t samba-tool dns add <Your-AD-DNS-Server-IP-or-hostname> samdom.example.com demo A 192.168.0.24"
echo
echo "Do not forget to open the LDAP port on your LDAP/AD Server(s)!:"
echo -e "\t- 389 (Default LDAP)"
echo -e "\t- 636 (Default LDAPS)"

exit