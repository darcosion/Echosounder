#! /usr/bin/env python3

import ipaddress
import itertools
import json
import platform
import shutil
import sys
from typing import Dict, Optional, List, Tuple, TextIO

import dns.resolver
import dns.reversename
import netifaces
import nmap
import scapy
from impacket import nt_errors
from impacket.smbconnection import SMBConnection, SessionError
from scapy.arch import get_if_addr, get_if_hwaddr
from scapy.config import conf
from scapy.layers.inet import IP, ICMP, traceroute, TracerouteResult
from scapy.layers.l2 import getmacbyip
from scapy.packet import Packet
from scapy.sendrecv import srp


def check_nmap_exist() -> bool:
    """ Check Nmap is installed, return True if installed, False otherwise"""
    return shutil.which("nmap") is not None


def get_address_family() -> Dict[str: int]:
    """
    Return the number referring to a particular address family
    example: AF_LINK (= link layer interface, e.g. Ethernet) --> 18
    """
    return {'IPv4': netifaces.AF_INET, 'IPv6': netifaces.AF_INET6, 'Ethernet': netifaces.AF_LINK}


def get_interfaces() -> List[str]:
    """ Return the list of interface identifiers for the machine """
    return netifaces.interfaces()


def get_interface_info(interface) -> Dict or List[Dict]:
    """ Asks for the info of a particular interface """
    return netifaces.ifaddresses(interface)


def from_ipnetmask_get_ipcidr(ipnetmask) -> ipaddress.IPv4Network or ipaddress.IPv6Network:
    """ from an IP Net Mask, return an  IPv4Network or IPv6Network corresponding to a IP CIDR """
    return str(ipaddress.ip_network(ipnetmask, strict=False))


def get_host_and_gateway() -> Dict:
    """
    Grab the
        - IP and mac of local machine
        - Gateway IP
    """
    local_ip: str = get_if_addr(conf.iface)
    local_mac: str = get_if_hwaddr(conf.iface)

    router_hop_1: Optional[str] = conf.route.route("0.0.0.0")[2]
    router_hop_1_mac: Optional[str] = getmacbyip(router_hop_1)
    gateway_vendor = None
    with open("ouiinfo/oui.json") as oui_json:
        OUIJson = json.loads(oui_json.read())
        oui_json.close()
        router_mac_oui = router_hop_1_mac[0:8].replace(':', '').upper()
        for i in OUIJson:
            if router_mac_oui == i[0]:
                gateway_vendor = i[1]
    return {"local_ip": local_ip, "local_mac": local_mac, "gateway_ip": router_hop_1, "gateway_mac": router_hop_1_mac,
            "gateway_vendor": gateway_vendor}


def reverse_ptr_local_scan(target_ip) -> list:
    """ Perform a reverse PTR local scan """
    list_ptr: List[str] = []
    try:
        no = dns.reversename.from_address(target_ip)
        answers = dns.resolver.resolve(no, 'PTR')
        for rdata in answers:
            list_ptr.append(str(rdata))
    except:
        list_ptr.append('no ptr')
    return list_ptr


def arp_local_scan(target_ip: str) -> Tuple[List[str], List[str]]:
    """
    ARP SCAN for local machines
    scapy.layers.l2.ARP create an ARP object from the target IP
        "pdst" option = Target protocol address (TPA)
    
    ff:ff:ff:ff:ff:ff broadcast mac address
    """
    stacked_protocols: tuple = stacked_protocol(target_ip)
    clients: List[dict] = []
    ip_list, mac_list = get_mac_and_ip()

    for sent, received in stacked_protocols:
        clients.append({'ip': received.psrc, 'mac': received.hwsrc})
    for client in clients:
        ip_list.append((client['ip']))
        mac_list.append((client['mac']))
    return ip_list, mac_list


def stacked_protocol(target_ip: str) -> tuple:
    """ Get the stacked protocols """
    arp = scapy.layers.l2.ARP(pdst=target_ip)
    ether = scapy.layers.l2.Ether(dst="ff:ff:ff:ff:ff:ff")
    return stack_protocols(arp, ether)


def stack_protocols(arp, ether) -> tuple:
    """ Actually does the stacking of the protocols """
    packet = ether / arp
    return srp(packet, timeout=3, verbose=0)[0]


def get_mac_and_ip() -> Tuple[List[str], List[str]]:
    """ Create and returns the lists of all IP and Mac addresses """
    ip_list: List[str] = []
    mac_list: List[str] = []
    ip_list.append(scapy.arch.get_if_addr(conf.iface))
    mac_list.append(scapy.arch.get_if_hwaddr(conf.iface))
    return ip_list, mac_list


def data_creation_arp_scan(target_ip) -> List[dict]:
    """ Creates the data associated to an ARP scan and returns it to the front end """
    ip_list, mac_list = arp_get_ip_mac_from_scan(target_ip)
    global_list: List[Dict[str: str]] = []

    with open("ouiinfo/oui.json") as oui_json:
        oui_json = load_json_data(oui_json)
        for i in range(len(ip_list)):
            oui_mac: str = mac_list[i][0:8].replace(':', '').upper()
            current_ip, current_mac = scan_current_ip_mac(i, ip_list, mac_list)
            ip_and_mac_to_dict: Dict[str: str, str: str] = {"IP": current_ip, "mac": current_mac}
            scan_retrieve_vendor(oui_json, ip_and_mac_to_dict, oui_mac)
            global_list.append(ip_and_mac_to_dict)
    return global_list


def scan_retrieve_vendor(oui_json, scan_dict: dict, oui_mac: str):
    """ Adds the "vendor" category to the dict provided
    Dict can be either:
    - {ip, mac} --> from data_creation_arp_scan()
    - {ip, mac, os} --> from data_creation_fast_ping()
    """
    for i_oui in oui_json:
        if oui_mac == i_oui[0]:
            scan_dict['vendor'] = i_oui[1]
            break


def scan_current_ip_mac(i: int, ip_list: List[str], mac_list: List[str]) -> Tuple[str, str]:
    """Retrieves the current ip and mac """
    return ip_list[i], mac_list[i]


def arp_get_ip_mac_from_scan(target_ip) -> Tuple[List[str], List[str]]:
    """ Retrieves the [IP, Mac] addresses from a scan """
    return_scan: List[List[str], List[str]] = list(arp_local_scan(target_ip))
    return return_scan[0], return_scan[1]


def load_json_data(oui_json: TextIO):
    """ Load the data from the filename provided. OUI = Organization Unique Identifier """
    oui_json = json.loads(oui_json.read())
    oui_json.close()
    return oui_json


def data_creation_fast_ping(target_ip: str) -> List[Dict[str, str]]:
    """ Creates the data associated to a fast ping scan and returns it to the front end """
    ip_list, mac_list, os_list = fast_ping_get_ip_mac_os_from_scan(target_ip)
    global_list: List[Dict[str, str]] = []

    with open("ouiinfo/oui.json") as oui_json:
        oui_json = load_json_data(oui_json)
        for i in range(len(ip_list)):
            oui_mac: str = current_mac[0:8].replace(':', '').upper()
            current_ip, current_mac = scan_current_ip_mac(i, ip_list, mac_list)
            current_os: str = os_list[i]
            ip_mac_and_os_to_dict: Dict[str: str, str: str, str: str] = \
                {"IP": current_ip, "mac": current_mac, "OS": current_os}
            scan_retrieve_vendor(oui_json, ip_mac_and_os_to_dict, oui_mac)
            global_list.append(ip_mac_and_os_to_dict)
    return global_list


def fast_ping_get_ip_mac_os_from_scan(target_ip: str) -> Tuple[List[str], List[str], List[str]]:
    """ Retrieves [IP, Mac, OS] from a scan """
    return_scan = list(recon_fast_ping(target_ip))
    return return_scan[0], return_scan[1], return_scan[2]


def recon_fast_ping(target_ip: str) -> Tuple[List[str], List[str], List[str]]:
    """ Does a fast ping to the target IP """
    os_ttl_list: List[str] = [platform.system()]
    local_ip: str = scapy.arch.get_if_addr(conf.iface)
    ttl_list: list = []
    ip_list, mac = arp_local_scan(target_ip)
    for ip in ip_list:
        append_to_ttl_list(ip, local_ip, ttl_list)
    append_os_ttl(os_ttl_list, ttl_list)
    return ip_list, mac, os_ttl_list


def append_to_ttl_list(ip, local_ip, ttl_list) -> None:
    """ Modifies in-place the list of all TTLs """
    if ip == local_ip:
        ttl_list.append('0')
    else:
        packet: Optional[Packet] = scapy.sendrecv.sr1(IP(dst=ip) / ICMP(), timeout=15)
        if packet is None:
            ttl_list.append('0')
        else:
            ttl_list.append(packet.ttl)


def append_os_ttl(os_ttl_list, ttl_list) -> None:
    """
    Appends the OS from the corresponding TTL
    cf. https://0xbharath.github.io/art-of-packet-crafting-with-scapy/network_recon/os_detection/index.html
    """
    for i in range(len(ttl_list)):
        if ttl_list[i] == 64 or ttl_list[i] == 255:
            os_ttl_list.append("Linux/UNIX")
        elif ttl_list[i] == 128:
            os_ttl_list.append("Windows")
        elif ttl_list[i] == 254:
            os_ttl_list.append("Cisco")
        else:
            os_ttl_list.append("Unknown")


def creation_data_nmap(ip_address) -> dict:
    nm: nmap.PortScanner = nmap.PortScanner()
    nmap_scan_result: dict = nm.scan(hosts=ip_address, arguments='-O')
    scan_res_to_str: str = json.dumps(nmap_scan_result)
    scan_res_to_dict = json.loads(scan_res_to_str)
    accuracy, name, os_family, vendor = nmap_get_name_vendor_os_accuracy(ip_address, scan_res_to_dict)
    return {
        "IP": ip_address,
        "nom": name,
        "vendeur": vendor,
        "osfamily": os_family,
        "accuracy": accuracy,
    }


def nmap_get_name_vendor_os_accuracy(ip_address, scan_res_to_dict) -> Tuple[str, str, str, str]:
    """ Get the name, vendor, OS and accuracy of an Nmap scan """
    try:
        name: str = scan_res_to_dict["scan"][ip_address]["osmatch"][0]["name"]
        vendor: str = scan_res_to_dict["scan"][ip_address]["osmatch"][0]["osclass"][0]["vendor"]
        os_family: str = scan_res_to_dict["scan"][ip_address]["osmatch"][0]["osclass"][0]["osfamily"]
        accuracy: str = scan_res_to_dict["scan"][ip_address]["osmatch"][0]["accuracy"]
    except:
        name = "unknown"
        vendor = "unknown"
        os_family = "unknown"
        accuracy = "unknown"
    return accuracy, name, os_family, vendor


def null_session_smb_enumeration(target_ip: str) -> Dict:
    """ 
    Using srsvc to list some information, this can use blank credentials as well as "Guest" and "" as user and password
    """
    username, password = "", ""
    conn: Optional[SMBConnection] = None

    try:
        conn = try_smb_connection(password, target_ip, username)
    except OSError:
        print(f"SMB NULL SESSION connection error")
        sys.exit(1)
    except SessionError as e:
        if e.getErrorCode() == nt_errors.STATUS_ACCESS_DENIED:
            pass
        else:
            print("NULL 2:", e)
    finally:
        domain_dns, domain_netbios, host_dns, host_netbios, is_signing, server_os = null_session_smb_enum_var(conn)

    return {
        'host_dns': host_dns, 'domain_dns': domain_dns, 'domain_netbios': domain_netbios, 'host_netbios': host_netbios,
        'server_os': server_os, 'is_signing': is_signing
    }


def try_smb_connection(password, target_ip, username):
    """ Try to initiate an SMB connection """
    conn: SMBConnection = SMBConnection(target_ip, target_ip)
    conn.login(username, password)
    try_smb_connect_tree(conn)
    conn.close()
    return conn


def try_smb_connect_tree(conn: SMBConnection):
    """ Try to enumerate"""
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
        print("NULL 1:", e)


def null_session_smb_enum_var(conn: SMBConnection):
    """ Returns the content retrieved with the SMB NULL session """
    host_netbios = conn.getServerName() if conn.getServerName().rstrip('\x00') else "-"
    domain_netbios = conn.getServerDomain() if conn.getServerDomain().rstrip('\x00') else "-"
    host_dns = conn.getServerDNSHostName() if conn.getServerDNSHostName().rstrip('\x00') else "-"
    domain_dns = conn.getServerDNSDomainName() if conn.getServerDomain().rstrip('\x00') else "-"
    is_signing = conn.isSigningRequired()
    server_os = conn.getServerOS()
    return domain_dns, domain_netbios, host_dns, host_netbios, is_signing, server_os


def retrieve_services_from_scan(target_ip, port_start: int, port_end: int) -> List[dict]:
    """ Retrieves the services from a scan """
    return retrieve_services([target_ip], nmap.PortScanner(), port_start=port_start, port_end=port_end)


def nmap_get_protocol_details(global_list: List[Dict], nm: nmap.PortScanner) -> List[Dict]:
    for i in nm.all_hosts():
        for protocol in nm[i].all_protocols():
            for k_port, content in nm[i][protocol].items():
                global_list.append({
                    "IP": i,
                    "protocol": protocol,
                    "port": str(k_port),
                    "result": nm[i][protocol][k_port],
                })
    return global_list


def retrieve_services(ip_list: List[str], nm: nmap.PortScanner, port_start: int, port_end: int) -> List[dict]:
    """ Extract the services data after performing an nmap scan """
    global_list: List[dict] = []
    try:
        for i in range(len(ip_list)):
            nm.scan(ip_list[i], str(port_start) + '-' + str(port_end), arguments="-sV")
            return nmap_get_protocol_details(global_list, nm)
    except KeyError:
        global_list.append({})
    return global_list


def retrieve_top_services() -> List[Dict]:
    """ Retrieve the top services """
    nm = nmap.PortScanner()
    global_list: List[dict] = []
    try:
        return nmap_get_protocol_details(global_list, nm)
    except KeyError:
        global_list.append({})
    return global_list


def fingerprint_ssh(target_ip: str) -> List[Dict]:
    """ Fingerprints the SSH service """
    nm = nmap.PortScanner()
    nm.scan(target_ip, arguments="-p 22 --script ssh-hostkey --script-args ssh_hostkey=full")
    return nmap_get_protocol_details([], nm)


def scan_snmp_info(target_ip: str) -> List[Dict]:
    """ Performs an SNMP scan and gets its informations """
    nm = nmap.PortScanner()
    nm.scan(target_ip, arguments="-sU -p 161 --script snmp-info")
    return nmap_get_protocol_details([], nm)


def scan_snmp_netstat(target_ip: str) -> List[Dict]:
    """ Performs an SNMP netstat scan and gets its informations """
    nm = nmap.PortScanner()
    nm.scan(target_ip, arguments="-sU -p 161 --script snmp-netstat")
    return nmap_get_protocol_details([], nm)


def scan_snmp_processes(target_ip: str) -> List[Dict]:
    """ Performs an SNMP processes scan and gets its informations """
    nm = nmap.PortScanner()
    nm.scan(target_ip, arguments="-sU -p 161 --script snmp-processes")
    return nmap_get_protocol_details([], nm)


def scan_ntp_info(target_ip: str) -> List[Dict]:
    """ Performs an NTP info scan and gets its informations """
    nm = nmap.PortScanner()
    nm.scan(target_ip, arguments="-sU -p 123 --script ntp-info")
    return nmap_get_protocol_details([], nm)


def scan_rdp_info(target_ip: str) -> List[Dict]:
    """ Performs an RDP info scan and gets its informations """
    nm = nmap.PortScanner()
    nm.scan(target_ip, arguments="-p 3389 --script rdp-ntlm-info")
    return nmap_get_protocol_details([], nm)


def data_creation_services_discovery(target_ip: str, port_start: int = 0, port_end: int = 400) -> List[dict]:
    """ Service discovery using nmap """
    return retrieve_services_from_scan(target_ip, port_start=port_start, port_end=port_end)


def traceroute_cidr_scan(target_cidr: str) -> List[List[dict]]:
    """
    Performs an traceroute CIDR scan and gets its informations
    // 4  is used as a step to take at most 5 IPs
    """
    target_hosts = ipaddress.IPv4Network(target_cidr)
    result: List[List[Dict]] = []
    slicer = target_hosts.num_addresses // 4
    if slicer < 1:
        slicer = 1
    for i in itertools.islice(target_hosts, 0, None, slicer):
        result.append(traceroute_scan(str(i)))
    return result


def traceroute_scan(target: str = "142.250.75.238") -> List[Dict]:
    """ Performs a traceroute scan """
    as_retrieved: Optional[List[ipaddress.IPv4Network[ipaddress.IPv4Address]]] = None
    list_return_ip: List[Dict] = []
    p, _ = traceroute(target)
    return traceroute_get_return_ip(list_return_ip, p, target)


def traceroute_get_return_ip(list_return_ip: List[Dict], p: TracerouteResult, target: str) -> List[Dict]:
    if target in p.get_trace().keys():
        p = p.get_trace()[target]
        with open('asinfo/routeviews-prefix2as-latest.json', 'r') as list_cidr:
            list_ip_cidr = [[ipaddress.IPv4Network(i[0]), i[1]] for i in json.loads(list_cidr.read())]
            list_cidr.close()
            list_return_ip = traceroute_update_ip_list(list_return_ip, p, list_ip_cidr)
        return list_return_ip


def traceroute_update_ip_list(list_return_ip: List[Dict], p: TracerouteResult, list_ip_cidr) -> List[Dict]:
    """
    Update the IP list of the traceroute scan
    Cette sorcellerie permet de sortir toutes les IPs d'un même AS sur la route
    et de s'arrêter dès qu'on a un AS différent.
    """
    for key, value in p.items():
        ip = ipaddress.IPv4Address(value[0])
        if ip.is_private:
            list_return_ip.append([value[0], [None, None]])
            continue
        for current_cidr in list_ip_cidr:
            if ip in current_cidr[0]:
                if as_retrieved is None:
                    as_retrieved = current_cidr[1]
                elif as_retrieved == current_cidr[1]:
                    continue
                else:
                    return list_return_ip
                list_return_ip.append([value[0], [str(current_cidr[0]), current_cidr[1]]])
                break
    return list_return_ip


def scan_dhcp_discover(target_cidr: str) -> List:
    """ Performs a DHCP discover scan using Nmap """
    nm = nmap.PortScanner()
    result: List = []
    try:
        nm.scan(target_cidr, arguments="-F --script broadcast-dhcp-discover")
        for i in nm.all_hosts():
            if 'addresses' in nm[i].keys():
                result.append(nm[i]['addresses'])

    except Exception as e:
        print(e)
        return []
    return result


if __name__ == "__main__":
    print("TEST")
    print(scan_dhcp_discover('192.168.1.0/24'))
