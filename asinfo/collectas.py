#! /usr/bin/env python3

import requests, gzip
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
    print(data_url)
    data_response = requests.get(url + data_url).content
    print(data_response)
    data_response = gzip.decompress(data_response)
    with open('routeviews-prefix2as-latest.pfx2as', 'wb') as filepfx:
        filepfx.write(data_response)
        filepfx.close()


if __name__ == "__main__":
    get_prefix2as_data()
