#! /usr/bin/env python

from scapy.all import *
import socket, sys, time
from pprint import pprint
import netifaces
import time
import nmap
import json

def ARP_LOCAL_SCAN(target_ip="172.20.10.4/28"):
    """
    ARP SCAN pour les machines locales
    """
    routerhop1 = conf.route.route("0.0.0.0")[2]
    #récuperation de l'adresse IP locale
    #172.20.10.4/28 -- 192.168.1.0/24
    arp = ARP(pdst=target_ip)
    # ff:ff:ff:ff:ff:ff broadcast adresse mac
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    # stack les protocoles
    packet = ether/arp
    result = srp(packet, timeout=3, verbose=0)[0]
    #initialisation de la liste des clients
    clients = []
    ip=[]
    mac=[]
    ip.append(get_if_addr(conf.iface))
    mac.append(get_if_hwaddr(conf.iface))

    for sent, received in result:
        # toutes les réponses sont implémentés dans la liste clients
        clients.append({'ip': received.psrc, 'mac': received.hwsrc})
    # affichage des clients
    for client in clients:
        ip.append((client['ip']))
        mac.append((client['mac']))
    #mac = getmacbyip(IPIPIP) pour avoir l'adresse mac avec une IP
    
    return(ip, mac, routerhop1)


def TEMPLATE():
    """
    grab l'ip locale de la machine ainsi que l'adresse mac
    """
    iplocale = get_if_addr(conf.iface)
    maclocale = get_if_hwaddr(conf.iface)

    routerhop1 = conf.route.route("0.0.0.0")[2]
    routerhop1mac = getmacbyip(routerhop1)
    return iplocale, maclocale, routerhop1, routerhop1mac

def out_in_json(i):
    nm = nmap.PortScanner()
    a = nm.scan(hosts= i, arguments='-O')
    b = json.dumps(a)
    ab = json.loads(b)
    try :
        nom = (ab["scan"][i]["osmatch"][0]["name"])
        vendeur = (ab["scan"][i]["osmatch"][0]["osclass"][0]["vendor"])
        osfamily = (ab["scan"][i]["osmatch"][0]["osclass"][0]["osfamily"])
        accuracy = (ab["scan"][i]["osmatch"][0]["accuracy"])
    except:
        nom = "uknown"
        vendeur = "uknown"
        osfamily = "uknown"
        accuracy = "uknown"

    return(nom, vendeur, osfamily, accuracy)

def creation_data_nmap(machines):
    iter = out_in_json(machines)

    result = {
        "IP" : machines,
        "nom" : iter[0],
        "vendeur" : iter[1],
        "osfamily" : iter[2],
        "accuracy" : iter[3],
    }
    return result

def iteraliste(target):
    liste_ip = []

    for i in target:
        liste_ip.append(creation_data_nmap(i))

    return liste_ip


def recon_fast_ping (a):
    IP_local = get_if_addr(conf.iface)
    liste_ttl = []
    os_liste_ttl = []
    plateforme_hote = platform.system()
    os_liste_ttl.append(plateforme_hote)

    retour_de_scan = ARP_LOCAL_SCAN(2)
    ip = retour_de_scan[0]
    mac = retour_de_scan[1]

    for i in ip :
        if i == IP_local:
            liste_ttl.append('0')
        else:
            aaa = sr1(IP(dst=(i))/ICMP())
            liste_ttl.append(aaa.ttl)

    for z in range(len(liste_ttl)):
        if liste_ttl[z] == 64 or liste_ttl[z] == 255 :
            os_liste_ttl.append("Linux/UNIX")
        elif liste_ttl[z] == 128 :
            os_liste_ttl.append("Windows")
        elif liste_ttl[z] == 254 :
            os_liste_ttl.append("Cisco")

    return (os_liste_ttl)

if __name__ == "__main__":
    print("IUT")
    a = ARP_LOCAL_SCAN()
    print(iteraliste(a[0]))
