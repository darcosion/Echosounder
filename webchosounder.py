#! /usr/bin/env python3

from typing import List
import ipaddress, json
import echosounder
from flask import Flask, jsonify, render_template, request
from scapy.arch import get_if_addr
from scapy.config import conf

LOCAL_IP = get_if_addr(conf.iface)

app = Flask(__name__, template_folder='templates')
app.config["CACHE_TYPE"] = "null"


@app.route('/')
def index():
    return render_template("index.html")


@app.route('/json/health')
def health():
    return jsonify(nmap=echosounder.check_nmap_exist())

@app.route('/json/address_family')
def get_address_family():
    return jsonify(echosounder.get_address_family())

@app.route('/json/interfaces')
def get_interfaces():
    return jsonify(echosounder.get_interfaces())

@app.route('/json/interface/<interface>')
def get_interface_info(interface):
    return jsonify(echosounder.get_interface_info(interface))

@app.route('/json/arp_scan', methods=['POST'])
def scan_arp():
    if not if_contain_cible(request.json):
        return {'error': "malformed request"}
    else:
        local_ip_mac_and_gateway: dict = echosounder.get_host_and_gateway()
        local_ip_mac: List[dict] = echosounder.data_creation_arp_scan(request.json['cible'])
        return jsonify(local_data=local_ip_mac_and_gateway, scan=local_ip_mac, vlan=request.json['cible'])

@app.route('/json/fast_scan', methods=['POST'])
def scan_rapide():
    if not if_contain_cible(request.json):
        return {'error': "malformed request"}
    else:
        local_ip_mac_and_gateway: dict = echosounder.get_host_and_gateway()
        ip_mac_os: List[dict] = echosounder.data_creation_fast_ping(request.json['cible'])
        return jsonify(local_data=local_ip_mac_and_gateway, scan=ip_mac_os, vlan=request.json['cible'])

@app.route('/json/trace_scan', methods=['GET'])
def scan_trace_fuzzing():
    trace: List[dict] = echosounder.traceroute_scan()
    return jsonify(scan=trace)

@app.route('/json/trace_scan', methods=['POST'])
def scan_trace():
    if not if_contain_cible(request.json):
        return {'error': "malformed request"}
    else:
        trace: List[dict] = echosounder.traceroute_scan(request.json['cible'])
        return jsonify(scan=trace)

@app.route('/json/trace_cidr_scan', methods=['POST'])
def scan_trace_cidr():
    if not if_contain_cible(request.json):
        return {'error': "malformed request"}
    else:
        trace: List[List[dict]] = echosounder.traceroute_cidr_scan(request.json['cible'])
        return jsonify(scan=trace)

@app.route('/json/dhcp_cidr_scan', methods=['POST'])
def scan_dhcp_cidr():
    if not if_contain_cible(request.json):
        return {'error': "malformed request"}
    else:
        dhcp_ip: List[List[dict]] = echosounder.scan_dhcp_discover(request.json['cible'])
        return jsonify(scan=dhcp_ip)

@app.route('/json/profiling_scan', methods=['POST'])
def scan_profiling():
    if not if_contain_cible(request.json):
        return {'error': "malformed request"}
    else:
        return jsonify(scan=echosounder.creation_data_nmap(request.json['cible']))

@app.route('/json/services_scan', methods=['POST'])
def scan_services():
    if not if_contain_cible(request.json):
        return {'error': "malformed request"}
    elif("port_start" not in request.json):
        return jsonify(scan=echosounder.data_creation_services_discovery(request.json['cible']))
    else:
        return jsonify(scan=echosounder.data_creation_services_discovery(request.json['cible'], port_start=request.json['port_start'], port_end=request.json['port_end']))

@app.route('/json/services_fast_scan', methods=['POST'])
def scan_fast_services():
    if not if_contain_cible(request.json):
        return {'error': "malformed request"}
    else:
        return jsonify(scan=echosounder.retrieve_top_services(request.json['cible']))

@app.route('/json/reverse_ptr_scan', methods=['POST'])
def scan_reverse_ptr():
    if not if_contain_cible(request.json):
        return {'error': "malformed request"}
    else:
        return jsonify(scan=echosounder.reverse_ptr_local_scan(request.json['cible']))

@app.route('/json/fingerpting_ssh_scan', methods=['POST'])
def scan_fingerprint_ssh():
    if not if_contain_cible(request.json):
        return {'error': "malformed request"}
    else:
        return jsonify(scan=echosounder.fingerprint_ssh(request.json['cible']))

@app.route('/json/scan_info_smb', methods=['POST'])
def scan_info_smb():
    if not if_contain_cible(request.json):
        return {'error': "malformed request"}
    else:
        return jsonify(scan=echosounder.null_session_smb_enumeration(request.json['cible']))

@app.route('/json/scan_snmp_info', methods=['POST'])
def scan_snmp_info():
    if not if_contain_cible(request.json):
        return {'error': "malformed request"}
    else:
        return jsonify(scan=echosounder.scan_snmp_info(request.json['cible']))

@app.route('/json/scan_snmp_netstat', methods=['POST'])
def scan_snmp_netstat():
    if not if_contain_cible(request.json):
        return {'error': "malformed request"}
    else:
        return jsonify(scan=echosounder.scan_snmp_netstat(request.json['cible']))

@app.route('/json/scan_snmp_processes', methods=['POST'])
def scan_snmp_processes():
    if not if_contain_cible(request.json):
        return {'error': "malformed request"}
    else:
        return jsonify(scan=echosounder.scan_snmp_processes(request.json['cible']))

@app.route('/json/scan_ntp', methods=['POST'])
def scan_ntp_info():
    if not if_contain_cible(request.json):
        return {'error': "malformed request"}
    else:
        return jsonify(scan=echosounder.scan_ntp_info(request.json['cible']))

@app.route('/json/scan_rdp_info', methods=['POST'])
def scan_rdp_info():
    if not if_contain_cible(request.json):
        return {'error': "malformed request"}
    else:
        return jsonify(scan=echosounder.scan_rdp_info(request.json['cible']))

@app.route('/json/ip_to_as/<ip>', methods=['GET'])
def ip_to_as(ip):
    ip = ipaddress.IPv4Address(ip)
    as_retrieved = None
    with app.open_resource('asinfo/routeviews-prefix2as-latest.json', 'r') as listcidr:
        listipcidr = [ [ipaddress.IPv4Network(i[0]), i[1]] for i in json.loads(listcidr.read())]
        listcidr.close()
        for i in listipcidr:
            if(ip in i[0]):
                return jsonify(as_number=i[1], as_cidr=str(i[0]))
    return {'error': "no AS match"}
        

def if_contain_cible(test_target) -> bool:
    return 'cible' in test_target


if __name__ == "__main__":
    app.run(host=LOCAL_IP, port=5042, debug=True)
