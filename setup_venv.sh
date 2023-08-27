#!/bin/bash
if [[ ! $scriptname ]]; then
	scriptname="`echo $BASH_SOURCE|awk -F "/" '{print $NF}'`"
fi

workpath=$(pwd)
if [ -d $1 ]; then
	workpath=$1
else
	echo "Provided path is not a valid directory."
	exit 1
fi

if [ -z $req ]; then
	req="requirements.txt"
fi

if ! [[ $(dpkg -l python3) ]] || ! [[ $(dpkg -l python3-virtualenv) ]];then
	echo "Please install the following packages: python3 python3-virtualenv"
	exit 1
fi

echo "[SCRIPT] | Creating virtualenv."
virtualenv -p python3 "$workpath"

if [ $? -ne 0 ]; then
	echo "[ERROR] | Could not create virtualenv."
	exit 1
fi

echo "[SCRIPT] | Activating virtualenv"
. bin/activate

if [ $? -ne 0 ]; then
	echo "[ERROR] | Could not Activate virtualenv."
	exit 1
fi

echo "[SCRIPT] | Installing newest version of pip"
pip install --upgrade pip

if [ $? -ne 0 ]; then
	echo "[ERROR] | Could not install latest pip version."
	exit 1
fi

if [ -f "$workpath/$req" ]; then
	echo "[SCRIPT] | Installing requirements.txt dependencies"
	pip3 install -r "$workpath/$req"
fi

if [ $? -ne 0 ]; then
	echo "[ERROR] | Could not install pip requirements."
	exit 1
fi
