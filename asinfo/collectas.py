#! /usr/bin/env python3

import requests, gzip, json
from datetime import date

def get_prefix2as_data():
    date_url = date.today().strftime("%Y/%m/")
    url = "https://publicdata.caida.org/datasets/routing/routeviews-prefix2as/" + date_url
    data_response = requests.get(url).text.splitlines()
    data_response.reverse()
    data_url = None
    for i in data_response:
        if(i.startswith('      <a href="')):
            data_url = i[15:53]
            break
    data_response = requests.get(url + data_url).content
    data_response = gzip.decompress(data_response)
    with open('asinfo/routeviews-prefix2as-latest.pfx2as', 'wb') as filepfx:
        filepfx.write(data_response)
        filepfx.close()

def get_prefix2as_to_json():
    with open('asinfo/routeviews-prefix2as-latest.pfx2as', 'r') as filepfx:
        list_cidr_as = filepfx.readlines()
        list_cidr_as = [i.rstrip().replace('\t', '/', 1).split('\t') for i in list_cidr_as]
        filepfx.close()
        with open('asinfo/routeviews-prefix2as-latest.json', 'w') as filejson:
            filejson.write(json.dumps(list_cidr_as))
            filejson.close()

if __name__ == "__main__":
    get_prefix2as_data()
    get_prefix2as_to_json()
