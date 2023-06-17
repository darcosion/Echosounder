#!/usr/bin/env python3

import requests, csv, json

def get_oui_data():
    url = "http://standards-oui.ieee.org/oui/oui.csv"
    data_response = requests.get(url).content
    with open("ouiinfo/oui.csv", "w") as ouifile:
        ouifile.write(data_response.decode('utf8'))
        ouifile.close()


def get_ouicsv_to_json():
    with open("ouiinfo/oui.csv", 'r') as ouifile:
        reader = csv.DictReader(ouifile)
        listOUI = []
        for row in reader:
            listOUI.append([row['Assignment'], row['Organization Name']])
        ouifile.close()
        with open("ouiinfo/oui.json", "w") as ouijsonfile:
            ouijsonfile.write(json.dumps(listOUI))
            ouijsonfile.close()

if __name__ == "__main__":
    # ici on lance le code de téléchargement de la base oui
    get_oui_data()
    get_ouicsv_to_json()
