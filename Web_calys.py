#! /usr/bin/env python

from scapy.all import *
import socket, sys, time
import time
import nmap
import json
import Calys_module as Calysmod
from flask import Flask
from flask import jsonify

IPlocale = get_if_addr(conf.iface)

app = Flask(__name__)
app.config["CACHE_TYPE"] = "null"

@app.route('/')
def index():
    return "ouais"

@app.route('/json/collecte')
def all_data():
    a = Calysmod.ARP_LOCAL_SCAN()
    b = Calysmod.iteraliste(a[0])
    return(b)


if __name__ == "__main__":
    app.run(host=IPlocale ,debug=True)
