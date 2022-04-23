# ⚓ Echosounder

## 📓 Présentation 

Echosounder est un explorateur de réseau local proposant une visualisation par graphe.

Le cycle du pentest est généralement composé de 5 phases : 
 - Reconnaissance.
 - Intrusion.
 - Élévation de privilège.
 - Persistence.
 - Exfiltration de données sensibles.

Echosounder se place dans la phase de reconnaissance de ce cycle, en proposant une fois un accès à un réseau privé obtenu, la possibilité de l'explorer, et de sortir une visualisation dudit réseau.

### 🖼️ Screenshots

![example_scan](https://user-images.githubusercontent.com/16328515/159520183-253055a4-925d-4077-98c0-49b56746299f.png)


### 🔎 Fonctionnalités

 - Effectuer des scans d'un réseau local.
 - Obtenir une vue claire des réseaux locaux & distants liés à ce réseau local.
 - Identifier des machines sur les réseaux.
 - Identifier des services sur ces machines.
 - Avoir l'ensemble des machines et des réseaux affichés sur un graphe.
 - Avoir l'ensemble des données de machines et de réseaux dans un panel "data".
 - Exporter les graphs en JSON.
 - Importer les graphs en JSON.

### Ce que Echosounder n'est pas

 - Un remplaçant à nmap (Echosounder utilise nmap comme dépendance).
 - Un logiciel de "management des asset" (Echosounder ne propose que de la visualisation).
 - Un logiciel de "vulnerability assessement" (Echosounder identifie des services via nmap, mais ne vérifie pas les vulnérabilités).

## ⬇️ Installation

### Dépendances
 
 - nmap (https://nmap.org/)
 - Scapy (https://scapy.net/)
 - Impacket (https://github.com/SecureAuthCorp/impacket)
 - dnspython (https://www.dnspython.org/)

### Installation 

```bash
git clone https://github.com/darcosion/Echosounder
cd Echosounder
sudo apt install nmap
sudo pip3 install -r requirements.txt
# mise à jour de la base de données CIDR -> AS
python3 asinfo/collectas.py
# mise à jour de la base de données MAC -> OUI
python3 ouiinfo/collectoui.py
```
### Lancement 

```bash
sudo ./webchosounder.py
```
