#! /usr/bin/env python3

from scapy.all import *

import Calys_module as Calysmod
from flask import Flask, jsonify, render_template

IPlocale = get_if_addr(conf.iface)

app = Flask(__name__, template_folder='templates')
app.config["CACHE_TYPE"] = "null"

@app.route('/')
def index():
    return render_template("index.html")

@app.route('/json/collecte')
def all_data():
    a = Calysmod.TEMPLATE()
    b = Calysmod.ARP_LOCAL_SCAN(target_ip="192.168.1.0/24")
    c = Calysmod.iteraliste(b[0])
    return jsonify(local_data=a,
                    arp_scan=b,
                    nmap=c)

@app.route('/json/fast_scan')
def scan_rapide():
    a = Calysmod.TEMPLATE()
    l = Calysmod.creation_data_fast_ping('192.168.1.0/24')
    return jsonify(local_data=a, scan=l)

if __name__ == "__main__":
    app.run(host=IPlocale ,port=5042,debug=True)
