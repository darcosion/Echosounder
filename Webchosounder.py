#! /usr/bin/env python3

from scapy.all import *

import Echosounder as Echomod
from flask import Flask, jsonify, render_template

IPlocale = get_if_addr(conf.iface)

app = Flask(__name__, template_folder='templates')
app.config["CACHE_TYPE"] = "null"

@app.route('/')
def index():
    return render_template("index.html")

@app.route('/json/arp_scan')
def scan_arp():
    print("start arp scan")
    a = Echomod.TEMPLATE()
    b = Echomod.creation_data_scan_arp("192.168.1.0/24")
    print("return arp scan")
    return jsonify(local_data=a, scan=b)

@app.route('/json/fast_scan')
def scan_rapide():
    a = Echomod.TEMPLATE()
    l = Echomod.creation_data_fast_ping('192.168.1.0/24')
    return jsonify(local_data=a, scan=l)

if __name__ == "__main__":
    app.run(host=IPlocale ,port=5042,debug=True)
