#! /usr/bin/env python

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
    a = Calysmod.ARP_LOCAL_SCAN("192.168.1.0/24")
    b = Calysmod.iteraliste(a[0])
    return(b)


if __name__ == "__main__":
    app.run(host=IPlocale ,debug=True)
