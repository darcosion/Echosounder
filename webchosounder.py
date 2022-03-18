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

@app.route('/json/arp_scan', methods=['POST'])
def scan_arp():
    if not if_contain_cible(request.json):
        return {'error': "malformed request"}
    else:
        local_ip_mac_and_gateway: dict = echosounder.template()
        local_ip_mac: List[dict] = echosounder.data_creation_arp_scan(request.json['cible'])
        return jsonify(local_data=local_ip_mac_and_gateway, scan=local_ip_mac, vlan=request.json['cible'])


@app.route('/json/fast_scan', methods=['POST'])
def scan_rapide():
    if not if_contain_cible(request.json):
        return {'error': "malformed request"}
    else:
        local_ip_mac_and_gateway: dict = echosounder.template()
        ip_mac_os: List[dict] = echosounder.data_creation_fast_ping(request.json['cible'])
        return jsonify(local_data=local_ip_mac_and_gateway, scan=ip_mac_os, vlan=request.json['cible'])

@app.route('/json/trace_scan', methods=['GET'])
def scan_trace_fuzzing():
    local_ip_mac_and_gateway: dict = echosounder.template()
    ip_mac_os: List[dict] = echosounder.traceroute_scan()
    return jsonify(scan=ip_mac_os)

@app.route('/json/trace_scan', methods=['POST'])
def scan_trace():
    if not if_contain_cible(request.json):
        return {'error': "malformed request"}
    else:
        local_ip_mac_and_gateway: dict = echosounder.template()
        ip_mac_os: List[dict] = echosounder.traceroute_scan(request.json['cible'])
        return jsonify(scan=ip_mac_os)

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


@app.route('/json/reverse_ptr_scan', methods=['POST'])
def scan_reverse_ptr():
    if not if_contain_cible(request.json):
        return {'error': "malformed request"}
    else:
        return jsonify(scan=echosounder.reverse_ptr_local_scan(request.json['cible']))

@app.route('/json/scan_info_smb', methods=['POST'])
def scan_info_smb():
    if not if_contain_cible(request.json):
        return {'error': "malformed request"}
    else:
        return jsonify(scan=echosounder.null_session_smb_enumeration(request.json['cible']))

@app.route('/json/ip_to_as/<ip>', methods=['GET'])
def ip_to_as(ip):
    ip = ipaddress.IPv4Address(ip)
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
