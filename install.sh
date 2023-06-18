#!/bin/bash

if [ "$EUID" -ne 0 ]
  then echo "Please run as root"
  exit
fi
echo "Installation de nmap"
apt install nmap
echo "Installation des dépendances python"
pip install -r requirements.txt

echo "Collecte des AS-CIDR"
python3 asinfo/collectas.py
echo "Collecte des info OUI"
python3 ouiinfo/collectoui.py