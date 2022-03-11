#! /usr/bin/env python3

from scapy.all import *

import Echosounder as Echomod
from flask import Flask, jsonify, render_template, request

IPlocale = get_if_addr(conf.iface)

app = Flask(__name__, template_folder='templates')
app.config["CACHE_TYPE"] = "null"

@app.route('/')
def index():
    return render_template("index.html")

@app.route('/json/arp_scan', methods=['POST'])
def scan_arp():
    if(not ifContainCible(request.json)):
        return {'error' : "malformed request"}
    else:
        a = Echomod.TEMPLATE()
        b = Echomod.creation_data_scan_arp(request.json['cible'])
        return jsonify(local_data=a, scan=b)

@app.route('/json/fast_scan', methods=['POST'])
def scan_rapide():
    if(not ifContainCible(request.json)):
        return {'error' : "malformed request"}
    else:
        a = Echomod.TEMPLATE()
        l = Echomod.creation_data_fast_ping(request.json['cible'])
        return jsonify(local_data=a, scan=l)

def ifContainCible(testcible):
    return 'cible' in testcible


if __name__ == "__main__":
    app.run(host=IPlocale ,port=5042,debug=True)
