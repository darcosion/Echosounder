#!/usr/bin/env python3

import sys, shutil, itertools
from typing import Optional, List, Tuple
import json
import ipaddress
import platform

import netifaces
import dns.resolver, dns.reversename
import nmap
import scapy
from scapy.arch import get_if_addr, get_if_hwaddr
from scapy.config import conf
from scapy.layers.inet import IP, ICMP, traceroute
from scapy.layers.l2 import getmacbyip
from scapy.packet import Packet
from scapy.sendrecv import srp

from impacket import nt_errors
from impacket.smbconnection import SMBConnection, SessionError
from impacket.dcerpc.v5.transport import SMBTransport
from impacket.dcerpc.v5.lsad import hLsarOpenPolicy2, POLICY_LOOKUP_NAMES
import impacket.dcerpc.v5.srvs as srvs


def check_nmap_exist():
    # check Nmap is installed, return True if installed, False otherwise
    return shutil.which("nmap") is not None

def get_address_family():
    return {'IPv4' : netifaces.AF_INET,'IPv6' : netifaces.AF_INET6, 'Ethernet' : netifaces.AF_LINK}

def get_interfaces():
    return netifaces.interfaces()

def get_interface_info(interface):
    return netifaces.ifaddresses(interface)

def from_ipnetmask_get_ipcidr(ipnetmask):
    return str(ipaddress.ip_network(ipnetmask, strict=False))

def get_host_and_gateway() -> dict:
    """
    grab the
        - IP and mac of local machine
        - gateway IP
    """
    local_ip: str = get_if_addr(conf.iface)
    local_mac: str = get_if_hwaddr(conf.iface)

    router_hop_1: Optional[str] = conf.route.route("0.0.0.0")[2]
    router_hop_1_mac: Optional[str] = getmacbyip(router_hop_1)
    gateway_vendor = None
    with open("ouiinfo/oui.json") as ouijson:
        OUIJson = json.loads(ouijson.read())
        ouijson.close()
        routermacoui = router_hop_1_mac[0:8].replace(':', '').upper()
        for i in OUIJson:
            if(routermacoui == i[0]):
                gateway_vendor = i[1]
    return {"local_ip": local_ip, "local_mac": local_mac, "gateway_ip": router_hop_1, "gateway_mac": router_hop_1_mac, "gateway_vendor" : gateway_vendor}

def reverse_ptr_local_scan(target_ip) -> list:
    list_ptr = []
    try:
        no = dns.reversename.from_address(target_ip)
        answers = dns.resolver.resolve(no, 'PTR')
        for rdata in answers:
            list_ptr.append(str(rdata))
    except Exception as e:
        list_ptr.append('no ptr')
    return list_ptr

def arp_local_scan(target_ip) -> Tuple[List[str], List[str]]:
    """
    ARP SCAN for local machines
    """
    router_hop_1: Optional[str] = conf.route.route("0.0.0.0")[2]
    # retrieve local IP address
    # 172.20.10.4/28 -- 192.168.1.0/24
    arp = scapy.layers.l2.ARP(pdst=target_ip)

    # ff:ff:ff:ff:ff:ff broadcast mac address
    ether = scapy.layers.l2.Ether(dst="ff:ff:ff:ff:ff:ff")

    # stack the protocols
    packet = ether / arp
    result: tuple = srp(packet, timeout=3, verbose=0)[0]

    # initialisation de la liste des clients
    clients: List[dict] = []
    ip_list: List[str] = []
    mac_list: List[str] = []
    ip_list.append(scapy.arch.get_if_addr(conf.iface))
    mac_list.append(scapy.arch.get_if_hwaddr(conf.iface))

    for sent, received in result:  # all the responses are implemented in "clients"
        clients.append({'ip': received.psrc, 'mac': received.hwsrc})
    for client in clients:  # display the clients
        ip_list.append((client['ip']))
        mac_list.append((client['mac']))
    return (ip_list, mac_list)

def recon_fast_ping(target_ip) -> tuple:
    os_ttl_list: List[str] = [platform.system()]
    local_ip: str = scapy.arch.get_if_addr(conf.iface)
    ttl_list: list = []
    ip_list, mac = arp_local_scan(target_ip)

    for ip in ip_list:
        if ip == local_ip:
            ttl_list.append('0')
        else:
            packet: Optional[Packet] = scapy.sendrecv.sr1(IP(dst=ip) / ICMP(), timeout=15)
            if packet is None:
                ttl_list.append('0')
            else:
                ttl_list.append(packet.ttl)

    append_os_ttl(os_ttl_list, ttl_list)
    return ip_list, mac, os_ttl_list

def data_creation_arp_scan(target_ip) -> List[dict]:
    return_scan = list(arp_local_scan(target_ip))
    ip_list, mac_list = return_scan[0], return_scan[1]
    os_list = None
    global_list = []

    with open("ouiinfo/oui.json") as ouijson:
        OUIJson = json.loads(ouijson.read())
        ouijson.close()
        # ici on ajoute le type de OUI par MAC
        for i in range(len(ip_list)):
            oui = None
            ouimac = mac_list[i][0:8].replace(':', '').upper()
            current_ip: str = ip_list[i]
            current_mac: str = mac_list[i]
            ip_and_mac_to_dict = {
                "IP": current_ip,
                "mac": current_mac,
            }
            for ioui in OUIJson:
                if(ouimac == ioui[0]):
                    ip_and_mac_to_dict['vendor'] = ioui[1]
                    break
            global_list.append(ip_and_mac_to_dict)
    return global_list

def data_creation_fast_ping(target_ip) -> List[dict]:
    return_scan = list(recon_fast_ping(target_ip))
    ip_list, mac_list, os_list = return_scan[0], return_scan[1], return_scan[2]
    global_list = []

    with open("ouiinfo/oui.json") as ouijson:
        OUIJson = json.loads(ouijson.read())
        ouijson.close()
        for i in range(len(ip_list)):
            current_ip: str = ip_list[i]
            current_mac: str = mac_list[i]
            ouimac = current_mac[0:8].replace(':', '').upper()
            current_os: str = os_list[i]
            result = {
                "IP": current_ip,
                "mac": current_mac,
                "OS": current_os,
            }
            for ioui in OUIJson:
                if(ouimac == ioui[0]):
                    result['vendor'] = ioui[1]
                    break
            global_list.append(result)
    return global_list

def append_os_ttl(os_ttl_list, ttl_list) -> None:
    for z in range(len(ttl_list)):
        if ttl_list[z] == 64 or ttl_list[z] == 255:
            os_ttl_list.append("Linux/UNIX")
        elif ttl_list[z] == 128:
            os_ttl_list.append("Windows")
        elif ttl_list[z] == 254:
            os_ttl_list.append("Cisco")
        else:
            os_ttl_list.append("Unknown")

def creation_data_nmap(ip_address) -> dict:
    nm: nmap.PortScanner = nmap.PortScanner()
    nmap_scan_result: dict = nm.scan(hosts=ip_address, arguments='-O')
    scan_res_to_str: str = json.dumps(nmap_scan_result)
    scan_res_to_dict = json.loads(scan_res_to_str)

    try:
        name: str = scan_res_to_dict["scan"][machine]["osmatch"][0]["name"]
        vendor: str = scan_res_to_dict["scan"][machine]["osmatch"][0]["osclass"][0]["vendor"]
        osfamily: str = scan_res_to_dict["scan"][machine]["osmatch"][0]["osclass"][0]["osfamily"]
        accuracy: str = scan_res_to_dict["scan"][machine]["osmatch"][0]["accuracy"]
    except:
        name = "unknown"
        vendor = "unknown"
        osfamily = "unknown"
        accuracy = "unknown"

    return {
        "IP": ip_address,
        "nom": name,
        "vendeur": vendor,
        "osfamily": osfamily,
        "accuracy": accuracy,
    }

def null_session_smb_enumeration(target_ip):
    """ 
    Using srsvc to list some juicy information, this can use blank credentials as well as "Guest" and "" as user and password
    """
    username = ""
    password = ""

    try:
        conn = SMBConnection(target_ip, target_ip)
        conn.login(username, password)

        try:
            tree_id = conn.connectTree("IPC$")
            try:
                file_id = conn.openFile(tree_id, "srvsvc")
                conn.closeFile(tree_id, file_id)
            except SessionError as e:
                if e.getErrorCode() == nt_errors.STATUS_ACCESS_DENIED:
                    pass
                conn.disconnectTree(tree_id)
        except Exception as e:
            print("Fuck NULL 1:", e)

        conn.close()
    except OSError:
        print(f"Connection error")
        sys.exit(1)
    except SessionError as e:
        if e.getErrorCode() == nt_errors.STATUS_ACCESS_DENIED:
            pass
        else:
            print("Fuck NULL 2:", e)
    finally:
        host_netbios = conn.getServerName() if conn.getServerName().rstrip('\x00') else "-"
        domain_netbios = conn.getServerDomain() if conn.getServerDomain().rstrip('\x00') else "-"
        host_dns = conn.getServerDNSHostName() if conn.getServerDNSHostName().rstrip('\x00') else "-"
        domain_dns = conn.getServerDNSDomainName() if conn.getServerDomain().rstrip('\x00') else "-"
        is_signing = conn.isSigningRequired()
        server_os = conn.getServerOS() 

    smb_info = {}

    smb_info['host_dns'] = host_dns
    smb_info['domain_dns'] = domain_dns
    smb_info['domain_netbios'] = domain_netbios
    smb_info['host_netbios'] = host_netbios
    smb_info['server_os'] = server_os
    smb_info['is_signing'] = is_signing

    return smb_info

def retrieve_services_from_scan(target_ip, port_start: int, port_end: int) -> List[dict]:
    nm = nmap.PortScanner()  # instantiate nmap.PortScanner object

    global_list: List[dict] = retrieve_services([target_ip], nm, port_start=port_start, port_end=port_end)
    return global_list

def retrieve_services(ip_list: List[str], nm: nmap.PortScanner, port_start: int, port_end: int) -> List[dict]:
    """
    Extract the service data after performing an nmap scan
    """
    global_list: List[dict] = []
    try:
        for i in range(len(ip_list)):
            nmap_scan_result: dict = nm.scan(ip_list[i], str(port_start) + '-' + str(port_end), arguments="-sV")
            for i in nm.all_hosts():
                for protocol in nm[i].all_protocols():
                    for kport, content in nm[i][protocol].items():
                        global_list.append({
                            "IP": i,
                            "protocol" : protocol,
                            "port" : str(kport),
                            "result" : nm[i][protocol][kport],
                        })
            return global_list
    except KeyError:
        global_list.append({})
    return global_list

def retrieve_top_services(target_ip):
    nm = nmap.PortScanner()  # instantiate nmap.PortScanner object
    nmap_scan_result: dict = {}
    global_list: List[dict] = []
    try:
        nmap_scan_result = nm.scan(target_ip, arguments="-F")
        for i in nm.all_hosts():
            for protocol in nm[i].all_protocols():
                for kport, content in nm[i][protocol].items():
                    global_list.append({
                        "IP": i,
                        "protocol" : protocol,
                        "port" : str(kport),
                        "result" : nm[i][protocol][kport],
                    })
        return global_list
    except KeyError:
        global_list.append({})
    return global_list

def fingerprint_ssh(target_ip):
    nm = nmap.PortScanner()  # instantiate nmap.PortScanner object
    nmap_scan_result: dict = {}
    nmap_scan_result = nm.scan(target_ip, arguments="-p 22 --script ssh-hostkey --script-args ssh_hostkey=full")
    global_list: List[dict] = []
    for i in nm.all_hosts():
        for protocol in nm[i].all_protocols():
            for kport, content in nm[i][protocol].items():
                global_list.append({
                    "IP": i,
                    "protocol" : protocol,
                    "port" : str(kport),
                    "result" : nm[i][protocol][kport],
                })
    return global_list

def scan_snmp_info(target_ip):
    nm = nmap.PortScanner()  # instantiate nmap.PortScanner object
    nmap_scan_result: dict = {}
    nmap_scan_result = nm.scan(target_ip, arguments="-sU -p 161 --script snmp-info")
    global_list: List[dict] = []
    for i in nm.all_hosts():
        for protocol in nm[i].all_protocols():
            for kport, content in nm[i][protocol].items():
                global_list.append({
                    "IP": i,
                    "protocol" : protocol,
                    "port" : str(kport),
                    "result" : nm[i][protocol][kport],
                })
    return global_list

def scan_snmp_netstat(target_ip):
    nm = nmap.PortScanner()  # instantiate nmap.PortScanner object
    nmap_scan_result: dict = {}
    nmap_scan_result = nm.scan(target_ip, arguments="-sU -p 161 --script snmp-netstat")
    global_list: List[dict] = []
    for i in nm.all_hosts():
        for protocol in nm[i].all_protocols():
            for kport, content in nm[i][protocol].items():
                global_list.append({
                    "IP": i,
                    "protocol" : protocol,
                    "port" : str(kport),
                    "result" : nm[i][protocol][kport],
                })
    return global_list

def scan_snmp_processes(target_ip):
    nm = nmap.PortScanner()  # instantiate nmap.PortScanner object
    nmap_scan_result: dict = {}
    nmap_scan_result = nm.scan(target_ip, arguments="-sU -p 161 --script snmp-processes")
    global_list: List[dict] = []
    for i in nm.all_hosts():
        for protocol in nm[i].all_protocols():
            for kport, content in nm[i][protocol].items():
                global_list.append({
                    "IP": i,
                    "protocol" : protocol,
                    "port" : str(kport),
                    "result" : nm[i][protocol][kport],
                })
    return global_list

def scan_ntp_info(target_ip):
    nm = nmap.PortScanner()  # instantiate nmap.PortScanner object
    nmap_scan_result: dict = {}
    nmap_scan_result = nm.scan(target_ip, arguments="-sU -p 123 --script ntp-info")
    global_list: List[dict] = []
    for i in nm.all_hosts():
        for protocol in nm[i].all_protocols():
            for kport, content in nm[i][protocol].items():
                global_list.append({
                    "IP": i,
                    "protocol" : protocol,
                    "port" : str(kport),
                    "result" : nm[i][protocol][kport],
                })
    return global_list

def scan_rdp_info(target_ip):
    nm = nmap.PortScanner()  # instantiate nmap.PortScanner object
    nmap_scan_result: dict = {}
    nmap_scan_result = nm.scan(target_ip, arguments="-p 3389 --script rdp-ntlm-info")
    global_list: List[dict] = []
    for i in nm.all_hosts():
        for protocol in nm[i].all_protocols():
            for kport, content in nm[i][protocol].items():
                global_list.append({
                    "IP": i,
                    "protocol" : protocol,
                    "port" : str(kport),
                    "result" : nm[i][protocol][kport],
                })
    return global_list

def data_creation_services_discovery(target_ip, port_start: int = 0, port_end: int = 400) -> List[dict]:
    """
    Service discovery using nmap
    """
    return retrieve_services_from_scan(target_ip, port_start=port_start, port_end=port_end)

def traceroute_cidr_scan(targetcidr) -> List[List[dict]]:
    targethosts = ipaddress.IPv4Network(targetcidr)
    result = []
    slicer = targethosts.num_addresses // 4 # 4 sert de "pas" pour ne prendre que 5 IP au maximum
    if(slicer < 1):
        slicer = 1
    for i in itertools.islice(targethosts, 0, None, slicer): # parcours la range 5 fois via le slicer
        print(i)
        result.append(traceroute_scan(str(i)))
    return result

def traceroute_scan(target='142.250.75.238') -> List[dict]:
    as_retrieved = None
    list_return_ip = []
    p, r = traceroute(target)
    if(target in p.get_trace().keys()):
        p = p.get_trace()[target]
        with open('asinfo/routeviews-prefix2as-latest.json', 'r') as listcidr:
            listipcidr = [[ipaddress.IPv4Network(i[0]), i[1]] for i in json.loads(listcidr.read())]
            listcidr.close()
            # cette sorcellerie permet de sortir toute les IP d'un même AS sur la route et de s'arrêter dès qu'on a un AS différent.
            for k, v in sorted(p.items()):
                ip = ipaddress.IPv4Address(v[0])
                if(ip.is_private):
                    list_return_ip.append([v[0], [None, None]])
                    continue
                for i in listipcidr:
                    if(ip in i[0]):
                        if(as_retrieved == None):
                            as_retrieved = i[1]
                        elif(as_retrieved == i[1]):
                            None
                        else:
                            return list_return_ip
                        list_return_ip.append([v[0], [str(i[0]), i[1]]])
                        break
    return list_return_ip

def scan_dhcp_discover():
    nm = nmap.PortScanner()  # instantiate nmap.PortScanner object
    result = []
    try:
        nm.scan(target_cidr, arguments=" --script broadcast-dhcp-discover")
        for i in nm.all_hosts():
            if('addresses' in nm[i].keys()):
                result.append(nm[i]['addresses'])

    except Exception as e:
        print(e)
        return []
    return result

if __name__ == "__main__":
    print("TEST")
    print(scan_dhcp_discover1('192.168.1.0/24'))
