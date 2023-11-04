import os
import json

product = 'linux-image-unsigned-5.17.0-1012-oem'


results = {}
if os.path.isfile("/var/DB/license/ubuntu_license_db.json"):
    with open("/var/DB/license/ubuntu_license_db.json", "r") as f:
        jsondata = json.load(f)

    jsondata = jsondata['results']

    jsondata = list(filter(lambda x: (product == x['name']), jsondata))

    if jsondata:
        jsondata = jsondata[0]

    results['name'] = jsondata['name']
    results['license'] = jsondata['license']
    results['platform'] = jsondata['platform']
    results['version'] = jsondata['version']

print(results)

