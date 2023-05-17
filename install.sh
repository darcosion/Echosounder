#!/bin/bash

if [ "$EUID" -ne 0 ]
  then echo "Please run as root"
  exit
fi

apt install nmap
pip install -r requirements.txt

cd asinfo
python3 collectas.py