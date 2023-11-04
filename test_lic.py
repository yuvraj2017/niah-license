import requests
from bs4 import BeautifulSoup
import urllib
import json
import time

import xmltodict

results = {}


product = "libhtsengine-dev"
with open('/var/DB/license/ubuntu_license_db.json', 'r') as f:
    jsondata = json.load(f)
    data = jsondata['results']

    for d in data:
        if d['name'] == product:
            osname = d['platform']

print(osname)

link = "https://packages.ubuntu.com/%s/%s" % (osname, product)

print(link)



# with open ("druid_druid.json", "w") as x:
#     json.dump(results, x, indent=2)