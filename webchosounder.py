#! /usr/bin/env python3

from typing import List
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


@app.route('/json/arp_scan', methods=['POST'])
def scan_arp():
    if not if_contain_cible(request.json):
        return {'error': "malformed request"}
    else:
        local_ip_mac_and_gateway: dict = echosounder.template()
        local_ip_mac: List[dict] = echosounder.data_creation_arp_scan(request.json['cible'])
        return jsonify(local_data=local_ip_mac_and_gateway, scan=local_ip_mac)


@app.route('/json/fast_scan', methods=['POST'])
def scan_rapide():
    if not if_contain_cible(request.json):
        return {'error': "malformed request"}
    else:
        local_ip_mac_and_gateway: dict = echosounder.template()
        ip_mac_os: List[dict] = echosounder.data_creation_fast_ping(request.json['cible'])
        return jsonify(local_data=local_ip_mac_and_gateway, scan=ip_mac_os)


def if_contain_cible(test_target) -> bool:
    return 'cible' in test_target


if __name__ == "__main__":
    app.run(host=LOCAL_IP, port=5042, debug=True)
