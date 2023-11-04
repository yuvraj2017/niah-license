import json
import requests
import os
from niah_advisor import niah_advisor_scan


class crate_scan():
    def _init_(self):
        pass

    def get_package(self, packagename):
        url = 'https://crates.io/api/v1/crates/%s' % packagename
        response = requests.get(url)
        # print(url)
        jsondata  = response.json()
        latest_version = jsondata['crate']['newest_version']
        dep_url = 'https://crates.io/api/v1/crates/%s/%s/dependencies' % (packagename, latest_version)
        # print(dep_url)
        dep = requests.get(dep_url)
        dependency = dep.json()
        if 'dependency' in dependency:
            jsondata['crate']['dependencies'] = dependency
        else:
            jsondata['crate']['dependencies'] = {}

        if not os.path.exists("/tmp/lic_updates/crates"):
            os.makedirs("/tmp/lic_updates/crates")

        try:
            with open("/mnt/niahdb/packagesdb/crates/%s.json" % packagename, "w") as outfile:
                    json.dump(jsondata, outfile, indent=2)

            print("%s.json file created completely.....!!!!!! " %packagename)
        except:
            print("File not found..")

        with open("/tmp/lic_updates/crates/%s.json" % packagename, "w") as outfile:
                json.dump(jsondata, outfile, indent=2)


    
    def rssfeed(self):
        print("RSS Feed started")
        response = requests.get('https://crates.io/api/v1/summary')
        jsondata  = response.json()
        
        just_updated = jsondata['just_updated']
        new_crates = jsondata['new_crates']

        with open("/mnt/niahdb/niah-advisor/niah_pack/crates_update.json", "w") as f:
            json.dump(jsondata, f, indent=2)

        with open("/mnt/niahdb/niah-advisor/niah_pack/crates_update.json", "r") as f:
            jsondata = json.load(f)

        for updated in jsondata['just_updated']:
            packagename = updated['name']
            print(packagename)
            res = niah_advisor_scan()
            res.get_pack_details("crates", packagename)

        for new in jsondata['new_crates']:
            packagename = new['name']
            print(packagename)
            res = niah_advisor_scan()
            res.get_pack_details("crates", packagename)

    def scan(self):
        i = 1
        while True:
            params = {
                'page': '%s' % i,
            }

            response = requests.get('https://crates.io/api/v1/crates', params=params)
            jsondata  = response.json()
            
            for data in jsondata['crates']:
                packagename = data['name']
                print(packagename)
                self.get_package(packagename)	
                
            i = i + 1
        
            if i == 1884:
                break   

if __name__ == "__main__":
    res = crate_scan()
    res.scan()