import os
import sys
import json
from tqdm import tqdm
from bs4 import BeautifulSoup
from datetime import datetime
import re
import xmltodict
import requests
import glob
import urllib

class get_json_feeds():
    def __init__(self):
        pass

    def get_cves(self, cves):
        now = datetime.now()
        results = {}
        results['publishedDate'] = now.strftime("%d_%m_%Y_%H_%M_%S")

        results['data'] = []
        
        for cve in tqdm(cves.split(",")):
            if os.path.isfile("/var/DB/feeds/cves/%s.json" % cve):
            	with open("/var/DB/feeds/cves/%s" % cve, "r") as f:
                    res = json.load(f)

                    if res not in results['data']:
                        results['data'].append(res)

        return results

    def get_year(self, years):
        now = datetime.now()
        results = {}
        results['publishedDate'] = now.strftime("%d_%m_%Y_%H_%M_%S")

        results['data'] = []
        
        cves_files = []

        for year in years.split(","):
            for cve_file in os.listdir("/var/DB/feeds/cves/"):
                if "CVE-%s-" % year in str(cve_file):
                    cves_files.append("%s" % (cve_file))

        for cve_file_path in tqdm(cves_files):
            with open("/var/DB/feeds/cves/%s" % cve_file_path, "r") as f:
                res = json.load(f)

            if res not in results['data']:
                results['data'].append(res)

        return results

    def get_packages(self, packages, echosystem):
        now = datetime.now()
        results = {}
        results['publishedDate'] = now.strftime("%d_%m_%Y_%H_%M_%S")
        results['packages'] = {}

        for package in packages.split(","): 
            results['packages'][package] = {}

            vulns = self.get_package_vuln(package, echosystem)
            if vulns:
                results['packages'][package]['vulnerability'] = vulns
            else:
                results['packages'][package]['vulnerability'] = ''

            info = self.get_package_details(package, echosystem)
            if info:
                results['packages'][package]['info'] = info
            else:
                results['packages'][package]['info'] = ''

        return results
    
    def get_echosystem_vuln(self, echosystem):
        results = {}

        echosystems = ['c#', 'c', 'dart', 'elixir', 'go', 'java', 'javascript', 'php', 'python', 'ruby', 'rust']
        echosystem_platforms = ['ubuntu', 'debian', 'rhel', 'oracle_linux']

        if echosystem not in echosystem_platforms and echosystem not in echosystems:
            return False

        if echosystem in echosystem_platforms:
            with open("/var/DB/feeds/platform/%s/%s.json" % (echosystem, echosystem), "r") as f:
                results = json.load(f)
        else:
            with open("/var/DB/feeds/language/%s.json" % echosystem, "r") as f:
                jsondata1 = json.load(f)

                jsondata1 = jsondata1['results']

            with open("/var/DB/feeds/non-cve/noncve_feed.json", "r") as f:
                jsondata2 = json.load(f)

                jsondata2 = list(filter(lambda x:(echosystem == x['language']),jsondata2['results']))

            results = jsondata1 + jsondata2

        return results

    def get_package_vuln(self, package, echosystem):
        results = {}

        echosystems = ['c#', 'c', 'dart', 'elixir', 'go', 'java', 'javascript', 'php', 'python', 'ruby', 'rust']

        if echosystem not in echosystems:
            return False
        
        with open("/var/DB/feeds/language/%s.json" % echosystem, "r") as f:
            jsondata = json.load(f)

        results = list(filter(lambda x: (package == x['package']), jsondata["results"]))

        return results

    
    def get_package_details(self, osname, package, echosystem, check=False):
        results = {}

        if echosystem == "ubuntu":
            try:
                url = "https://packages.ubuntu.com/%s/%s" % (osname, package)
                print(url)
                

                page = requests.get(url)
                soup = BeautifulSoup(page.content, "html.parser")

                description = ''
                try:
                    if soup.findAll('div', {'id':'pdesc'}):
                        desc_text = soup.findAll('div', {'id':'pdesc'})[0]
                        description = desc_text.findAll('h2')[0].text
                except:
                    pass

                dependencies = []
                if soup.findAll('ul', {'class':'uldep'}):
                    if len(soup.findAll('ul', {'class':'uldep'})) > 1:
                        uls = soup.findAll('ul', {'class':'uldep'})[1]
                        for li in uls.findAll('li'):
                            if li.findAll('a'):
                                dep_pkg = li.findAll('a')[0].text
                                dependencies.append(dep_pkg)

                source_url = ''
                if soup.findAll('div', {'id':'pmoreinfo'}):
                    moreinfo = soup.findAll('div', {'id':'pmoreinfo'})[0]
                    for atag in moreinfo.findAll('a'):
                        if atag.text.strip() == "Homepage":
                            source_url = atag.get('href')

                pkg_version = ''
                h1txt = soup.findAll('h1')
                if re.findall(r'Package:\s+.*\s\((.*?)\s', str(h1txt)):
                    pkg_version = re.findall(r'Package:\s+.*\s\((.*?)\s', str(h1txt))[0]
                elif re.findall(r'Package:\s+.*\s\((.*?)\)', str(h1txt)):
                    pkg_version = re.findall(r'Package:\s+.*\s\((.*?)\)', str(h1txt))[0]

                results['author'] = ""
                results['description'] = description
                results['home_page'] = source_url
                results['license'] = ""
                results['package_url'] = source_url
                results['requires_version'] = dependencies
                results['version'] = pkg_version
                results['releases'] = ""

                if check:
                    results = {}
                    results['author'] = ""
                    results['description'] = description
                    results['home_page'] = source_url
                    results['license'] = ""
                    results['package_url'] = source_url
                    results['requires_version'] = dependencies
                    results['version'] = pkg_version
                    results['releases'] = ""


            except:
                
                file_path = glob.glob("/mnt/niahdb/packagesdb/platforms/ubuntu/**/%s/%s.json" % (package,package), recursive=True)

                print("111111",file_path)
                if file_path:
                    file_path = file_path[0]
                    print("File Path:", file_path)
                
                
                    if os.path.isfile(file_path):
                        print(file_path)
                        with open (file_path, "r") as f:
                            jsondata = json.load(f)

                        if 'current' in jsondata:
                            results['author'] = ""
                            results['description'] = ""
                            if 'description' in jsondata['current']:
                                results['description'] = jsondata['current']['description']

                            results['home_page'] = ''
                            if 'source_url' in jsondata['current']:
                                results['home_page'] = jsondata['current']['source_url']

                            results['license'] = ""
                            results['package_url'] = ""
                            if 'source_url' in jsondata['current']:
                                results['package_url'] = jsondata['current']['source_url']
                            
                            results['requires_dist'] = ""

                            if 'dependencies' in jsondata['current']:
                                results['requires_version'] = jsondata['current']['dependencies']
                            
                            results['version'] = ""
                            if 'pkg_version' in jsondata['current']:
                                results['version'] = jsondata['current']['pkg_version']

                            results['releases'] = ""


                            if check:
                                results = {}
                                results['author'] = ""
                                results['description'] = ""
                                if 'description' in jsondata['current']:
                                    results['description'] = jsondata['current']['description']

                                results['home_page'] = ''
                                if 'source_url' in jsondata['current']:
                                    results['home_page'] = jsondata['current']['source_url']

                                results['license'] = ""
                                results['package_url'] = ""
                                if 'source_url' in jsondata['current']:
                                    results['package_url'] = jsondata['current']['source_url']
                                
                                results['requires_dist'] = ""

                                if 'dependencies' in jsondata['current']:
                                    results['requires_version'] = jsondata['current']['dependencies']
                                results['version'] = ""
                                if 'pkg_version' in jsondata['current']:
                                    results['version'] = jsondata['current']['pkg_version']

                                results['releases'] = ""
                else:
                    print("No matching file found.")


        elif echosystem == "debian":

            try:
                print("Checking live data...")
                url = "https://packages.debian.org/%s/%s" % (osname, package)

                page = requests.get(url)
                soup = BeautifulSoup(page.content, "html.parser")

                description = ''
                try:
                    if soup.findAll('div', {'id':'pdesc'}):
                        desc_text = soup.findAll('div', {'id':'pdesc'})[0]
                        description = desc_text.findAll('h2')[0].text
                except:
                    pass

                dependencies = []
                if soup.findAll('ul', {'class':'uldep'}):
                    if len(soup.findAll('ul', {'class':'uldep'})) > 1:
                        uls = soup.findAll('ul', {'class':'uldep'})[1]
                        for li in uls.findAll('li'):
                            if li.findAll('a'):
                                dep_pkg = li.findAll('a')[0].text
                                dependencies.append(dep_pkg)

                source_url = ''

                if soup.findAll('div', {'id':'pmoreinfo'}):
                    moreinfo = soup.findAll('div', {'id':'pmoreinfo'})[0]
                    for atag in moreinfo.findAll('a'):
                        if atag.text.strip() == "Homepage":
                            source_url = atag.get('href')


                pkg_version = ''
                h1txt = soup.findAll('h1')
                if re.findall(r'Package:\s+.*\s\((.*?)\s', str(h1txt)):
                    pkg_version = re.findall(r'Package:\s+.*\s\((.*?)\s', str(h1txt))[0]
                elif re.findall(r'Package:\s+.*\s\((.*?)\)', str(h1txt)):
                    pkg_version = re.findall(r'Package:\s+.*\s\((.*?)\)', str(h1txt))[0]


                results['author'] = ""
                results['description'] = description
                results['home_page'] = source_url
                results['license'] = ""
                results['package_url'] = source_url
                results['requires_version'] = dependencies
                results['version'] = pkg_version
                results['releases'] = ""

                if check:
                    results = {}
                    results['author'] = ""
                    results['description'] = description
                    results['home_page'] = source_url
                    results['license'] = ""
                    results['package_url'] = source_url
                    results['requires_version'] = dependencies
                    results['version'] = pkg_version
                    results['releases'] = ""

            except:

                file_path = glob.glob("/mnt/niahdb/packagesdb/platforms/debian/**/%s/%s.json" % (package,package), recursive=True)

                if file_path:
                    file_path = file_path[0]
                
                    try:
                        if os.path.isfile(file_path):
                            print(file_path)
                            with open (file_path, "r") as f:
                                jsondata = json.load(f)

                            if 'current' in jsondata:
                                results['author'] = ""
                                results['description'] = ""
                                if 'description' in jsondata['current']:
                                    results['description'] = jsondata['current']['description']

                                results['home_page'] = ''
                                if 'source_url' in jsondata['current']:
                                    results['home_page'] = jsondata['current']['source_url']

                                results['license'] = ""
                                results['package_url'] = ""
                                if 'source_url' in jsondata['current']:
                                    results['package_url'] = jsondata['current']['source_url']
                                
                                results['requires_dist'] = ""

                                if 'dependencies' in jsondata['current']:
                                    results['requires_dist'] = jsondata['current']['dependencies']
                                results['version'] = ""
                                if 'pkg_version' in jsondata['current']:
                                    results['version'] = jsondata['current']['pkg_version']

                                results['releases'] = ""

                                if check:
                                    results = {}
                                    results['author'] = ""
                                    results['description'] = ""
                                    if 'description' in jsondata['current']:
                                        results['description'] = jsondata['current']['description']

                                    results['home_page'] = ''
                                    if 'source_url' in jsondata['current']:
                                        results['home_page'] = jsondata['current']['source_url']

                                    results['license'] = ""
                                    results['package_url'] = ""
                                    if 'source_url' in jsondata['current']:
                                        results['package_url'] = jsondata['current']['source_url']
                                    
                                    results['requires_dist'] = ""

                                    if 'dependencies' in jsondata['current']:
                                        results['requires_dist'] = jsondata['current']['dependencies']
                                    results['version'] = ""
                                    if 'pkg_version' in jsondata['current']:
                                        results['version'] = jsondata['current']['pkg_version']

                                    results['releases'] = ""

                    except:
                        print("No file Found..")

                else:
                    print("No loacl data found..")


        elif echosystem == "python":

            try:
                print("Checking live data...")
                url = "https://pypi.org/pypi/%s/json" % package
                print(url)
                responce = requests.get(url)
                jsondata = responce.json()

                if 'info' in jsondata:
                    results['author'] = ''
                    if 'author' in jsondata['info']:
                        results['author'] = jsondata['info']['author']

                    results['description'] = ''
                    if 'description' in jsondata['info']:
                        results['description'] = jsondata['info']['description']

                    results['home_page'] = ''
                    if 'home_page' in jsondata['info']:
                        results['home_page'] = jsondata['info']['home_page']

                    results['license'] = ''
                    if 'license' in jsondata['info']:
                        results['license'] = jsondata['info']['license']

                    results['package_url'] = ''
                    if 'package_url' in jsondata['info']:
                        results['package_url'] = jsondata['info']['package_url']

                    results['requires_dist'] = ''
                    if 'requires_dist' in jsondata['info']:
                        results['requires_dist'] = jsondata['info']['requires_dist']

                    results['requires_version'] = ''
                    if 'requires_python' in jsondata['info']:
                        results['requires_version'] = jsondata['info']['requires_python']

                    results['summary'] = ''
                    if 'summary' in jsondata['info']:
                        results['summary'] = jsondata['info']['summary']
                    
                    results['version'] = ''
                    if 'version' in jsondata['info']:
                        results['version'] = jsondata['info']['version']

                    results['releases'] = ''
                    if jsondata['releases']:
                        results['releases'] = jsondata['releases']


                    if check:
                        results = {}
                        results['author'] = ''
                        if 'author' in jsondata['info']:
                            results['author'] = jsondata['info']['author']

                        results['home_page'] = ''
                        if 'home_page' in jsondata['info']:
                            results['home_page'] = jsondata['info']['home_page']

                        results['license'] = ''
                        if 'license' in jsondata['info']:
                            results['license'] = jsondata['info']['license']

                        results['package_url'] = ''
                        if 'package_url' in jsondata['info']:
                            results['package_url'] = jsondata['info']['package_url']

                        results['summary'] = ''
                        if 'summary' in jsondata['info']:
                            results['summary'] = jsondata['info']['summary']
                        
                        results['version'] = ''
                        if 'version' in jsondata['info']:
                            results['version'] = jsondata['info']['version']

                    with open("/mnt/niahdb/packagesdb/pypi/%s.json" % package, "w") as outfile:
                        json.dump(jsondata, outfile, indent=2)

            except:
                
                print("Checking local data...")
                if os.path.isfile("/mnt/niahdb/packagesdb/pypi/%s.json" % package):
                    
                    with open("/mnt/niahdb/packagesdb/pypi/%s.json" % package, "r") as f:
                        jsondata = json.load(f)

                    if 'info' in jsondata:
                        results['author'] = ''
                        if 'author' in jsondata['info']:
                            results['author'] = jsondata['info']['author']

                        results['description'] = ''
                        if 'description' in jsondata['info']:
                            results['description'] = jsondata['info']['description']

                        results['home_page'] = ''
                        if 'home_page' in jsondata['info']:
                            results['home_page'] = jsondata['info']['home_page']

                        results['license'] = ''
                        if 'license' in jsondata['info']:
                            results['license'] = jsondata['info']['license']

                        results['package_url'] = ''
                        if 'package_url' in jsondata['info']:
                            results['package_url'] = jsondata['info']['package_url']

                        results['requires_dist'] = ''
                        if 'requires_dist' in jsondata['info']:
                            results['requires_dist'] = jsondata['info']['requires_dist']

                        results['requires_version'] = ''
                        if 'requires_python' in jsondata['info']:
                            results['requires_version'] = jsondata['info']['requires_python']

                        results['summary'] = ''
                        if 'summary' in jsondata['info']:
                            results['summary'] = jsondata['info']['summary']
                        
                        results['version'] = ''
                        if 'version' in jsondata['info']:
                            results['version'] = jsondata['info']['version']

                        results['releases'] = ''
                        if jsondata['releases']:
                            results['releases'] = jsondata['releases']

                        if check:
                            results = {}
                            results['author'] = ''
                            if 'author' in jsondata['info']:
                                results['author'] = jsondata['info']['author']

                            results['home_page'] = ''
                            if 'home_page' in jsondata['info']:
                                results['home_page'] = jsondata['info']['home_page']

                            results['license'] = ''
                            if 'license' in jsondata['info']:
                                results['license'] = jsondata['info']['license']

                            results['package_url'] = ''
                            if 'package_url' in jsondata['info']:
                                results['package_url'] = jsondata['info']['package_url']

                            results['summary'] = ''
                            if 'summary' in jsondata['info']:
                                results['summary'] = jsondata['info']['summary']
                            
                            results['version'] = ''
                            if 'version' in jsondata['info']:
                                results['version'] = jsondata['info']['version']
                    
                else:
                    print("No local data found...")
                


        elif echosystem == "php":

            try:
                url  = 'https://repo.packagist.org/p2/%s.json' % package
                print(url)
                response = requests.get(url)
                jsondata = response.json()
                jsondata = jsondata["packages"][f"{package}"]

                for data in jsondata:
                    j_data = data
                    break
                
                results['author'] = ''
                if 'authors' in j_data:
                    if 'name' in j_data['authors']:
                        results['author'] = j_data['authors']['name']

                results['description'] = ''
                if 'description' in j_data:
                    results['description'] = j_data['description']

                results['home_page'] = ''
                if 'homepage' in j_data:
                    results['home_page'] = j_data['homepage']

                results['package_url'] = ''

                results['license'] = ''
                if 'license' in j_data:
                    results['license'] = j_data['license']

                results['summary'] = ''

                results['version'] = ''
                if 'version' in j_data:
                    results['version'] = j_data['version']

                if check:
                    results = {}

                    results['author'] = ''
                    if 'authors' in j_data:
                        if 'name' in j_data['authors']:
                            results['author'] = j_data['authors']['name']

                    results['description'] = ''
                    if 'description' in j_data:
                        results['description'] = j_data['description']

                    results['home_page'] = ''
                    if 'homepage' in j_data:
                        results['home_page'] = j_data['homepage']

                    results['package_url'] = ''

                    results['license'] = ''
                    if 'license' in j_data:
                        results['license'] = j_data['license']

                    results['summary'] = ''

                    results['version'] = ''
                    if 'version' in j_data:
                        results['version'] = j_data['version']

                with open("/mnt/niahdb/packagesdb/composer/%s.json" % package.replace("/","_"), "w") as outfile:
                    json.dump(jsondata, outfile, indent=2)

            except:
                package = package.replace("/", "_")

                if os.path.isfile("/mnt/niahdb/packagesdb/composer/%s.json" % package):
                    print("Checking from files..!!")
                    with open("/mnt/niahdb/packagesdb/composer/%s.json" % package, "r") as f:
                        data = json.load(f)

                    # for data in jsondata:
                    #     jsondata = data
                    #     break
                    if 'versions' in data:
                        print("json")
                        jsondata = next(iter(data['versions'].values()))

                        print(jsondata)

                        results['author'] = ''
                        if 'author' in jsondata:
                            if 'name' in jsondata['author']:
                                results['author'] = jsondata['author']['name']

                        results['description'] = ''
                        if 'description' in jsondata:
                            results['description'] = jsondata['description']

                        results['home_page'] = ''
                        if 'homepage' in jsondata:
                            results['home_page'] = jsondata['homepage']
                        
                        
                        results['license'] = ''
                        if 'license' in jsondata:
                            results['license'] = jsondata['license']

                        results['package_url'] = ''
                        if 'github' in jsondata:
                            results['package_url'] = jsondata['github']

                        results['requires_dist'] = ''
                        if 'require' in jsondata:
                            results['requires_dist'] = jsondata['require']

                        results['requires_version'] = ''
                        if 'require' in jsondata:
                            results['requires_version'] = jsondata['require']


                        # requires_python = list(filter(lambda x: (echosystem == x['package']), jsondata['require']))
                        # results['requires_version'] = requires_python

                        results['summary'] = ''
                        if 'description' in jsondata:
                            results['summary'] = jsondata['description']

                        results['version'] = ''
                        if 'version' in jsondata:
                            results['version'] = jsondata['version']

                        results['releases'] = ''
                        if 'versions' in jsondata:
                            results['releases'] = jsondata['versions']

                        if check:
                            results = {}
                            results['author'] = ''
                            if 'author' in jsondata:
                                if 'name' in jsondata['author']:
                                    results['author'] = jsondata['author']['name']


                            results['home_page'] = ''
                            if 'homepage' in jsondata:
                                results['home_page'] = jsondata['homepage']

                            results['license'] = ''
                            if 'license' in jsondata:
                                results['license'] = jsondata['license']

                            results['package_url'] = ''
                            if 'github' in jsondata:
                                results['package_url'] = jsondata['github']

                            results['summary'] = ''
                            if 'description' in jsondata:
                                results['summary'] = jsondata['description']

                            results['version'] = ''
                            if 'version' in jsondata:
                                results['version'] = jsondata['version']
                    else:
                        jsondata = data[0]
                        print("list")
                        # print("data1111111111111", jsondata, "\n\n\n\n\n\n\n\n\n\n\n\n")
                        results['author'] = ''
                        if 'authors' in jsondata:
                            results['author'] = jsondata['authors']

                        results['description'] = ''
                        if 'description' in jsondata:
                            results['description'] = jsondata['description']

                        results['home_page'] = ''
                        if 'homepage' in jsondata:
                            results['home_page'] = jsondata['homepage']
                        
                        
                        results['license'] = ''
                        if 'license' in jsondata:
                            results['license'] = jsondata['license']

                        results['package_url'] = ''
                        if 'github' in jsondata:
                            results['homepage'] = jsondata['homepage']


                        results['summary'] = ''
                        if 'description' in jsondata:
                            results['summary'] = jsondata['description']

                        results['version'] = ''
                        if 'version' in jsondata:
                            results['version'] = jsondata['version']

                        if check:
                            results = {}
                            results['author'] = ''
                            if 'authors' in jsondata:
                                results['author'] = jsondata['authors']

                            results['description'] = ''
                            if 'description' in jsondata:
                                results['description'] = jsondata['description']

                            results['home_page'] = ''
                            if 'homepage' in jsondata:
                                results['home_page'] = jsondata['homepage']
                            
                            
                            results['license'] = ''
                            if 'license' in jsondata:
                                results['license'] = jsondata['license']

                            results['package_url'] = ''
                            if 'github' in jsondata:
                                results['homepage'] = jsondata['homepage']


                            results['summary'] = ''
                            if 'description' in jsondata:
                                results['summary'] = jsondata['description']

                            results['version'] = ''
                            if 'version' in jsondata:
                                results['version'] = jsondata['version']
                    
                else:
                    
                    print("No Local Data Found..")


        elif echosystem == "javascript":

            try:
                url = "https://registry.npmjs.org/%s" % package

                response = requests.get(url)
                jsondata = response.json()

                results['author'] = ''
                if 'author' in jsondata:
                    if 'name' in jsondata['author']:
                        results['author'] = jsondata['author']['name']

                results['description'] = ''
                if 'description' in jsondata:
                    results['description'] = jsondata['description']

                results['home_page'] = ''
                if 'homepage' in jsondata:
                    results['home_page'] = jsondata['homepage']

                results['license'] = ''
                if 'license' in jsondata:
                    results['license'] = jsondata['license']

                results['nodeVersion'] = ''
                results['npmVersion'] = ''
                results['summary'] = ''

                results['version'] = ''
                if 'dist-tags' in jsondata:
                    if 'latest' in jsondata['dist-tags']['latest']:
                        results['version'] = jsondata['current']['version']

                
                if check:
                    results = {}
                    results['author'] = ''
                    if 'author' in jsondata:
                        if 'name' in jsondata['author']:
                            results['author'] = jsondata['author']['name']

                    results['description'] = ''
                    if 'description' in jsondata:
                        results['description'] = jsondata['description']

                    results['home_page'] = ''
                    if 'homepage' in jsondata:
                        results['home_page'] = jsondata['homepage']

                    results['license'] = ''
                    if 'license' in jsondata:
                        results['license'] = jsondata['license']

                    results['nodeVersion'] = ''
                    results['npmVersion'] = ''
                    results['summary'] = ''

                    results['version'] = ''
                    if 'dist-tags' in jsondata:
                        if 'latest' in jsondata['dist-tags']['latest']:
                            results['version'] = jsondata['current']['version']

                with open("/mnt/niahdb/packagesdb/npm/%s.json" % package, "w") as outfile:
                    json.dump(jsondata, outfile, indent=2)

            except:

                if os.path.isfile("/mnt/niahdb/packagesdb/npm/%s.json" % package):
                    with open("/mnt/niahdb/packagesdb/npm/%s.json" % package, "r") as f:
                        jsondata = json.load(f)

                    print(jsondata)
                    results['author'] = ''
                    if 'current' in jsondata:
                        if 'author' in jsondata['current']:
                            if 'name' in jsondata['current']['author']:
                                results['author'] = jsondata['current']['author']['name']


                    results['description'] = ''
                    if jsondata['description']:
                        results['description'] = jsondata['description']

                    results['home_page'] = ""

                    results['license'] = ''
                    if jsondata['license']:
                        results['license'] = jsondata['license']

                    results['package_url'] = ''
                    if 'dist' in jsondata['current']:
                        if 'tarball' in jsondata['current']['dist']:
                            results['package_url'] = jsondata['current']['dist']['tarball']

                    results['requires_dist'] = ''
                    if 'latest' in jsondata['dist-tags']:
                        results['requires_dist'] = jsondata['dist-tags']['latest']

                    results['nodeVersion'] = ''
                    if 'nodeVersion' in jsondata['current']:
                        results['nodeVersion'] = jsondata['current']['nodeVersion']

                    results['npmVersion'] = ''
                    if 'npmVersion' in jsondata['current']:
                        results['npmVersion'] = jsondata['current']['npmVersion']

                    results['requires_version'] = ''
                    if 'dependencies' in jsondata['current']:
                        results['requires_version'] = jsondata['current']['dependencies']

                    results['summary'] = ""

                    results['version'] = ''
                    if 'version' in jsondata['current']:
                        results['version'] = jsondata['current']['version']
                    
                    results['releases'] = ''
                    if jsondata['versions']:
                        results['releases'] = jsondata['versions']

                    if check:
                        results = {}
                        results['author'] = ''
                        if 'current' in jsondata:
                            if 'author' in jsondata['current']:
                                if 'name' in jsondata['current']['author']:
                                    results['author'] = jsondata['current']['author']['name']

                        results['home_page'] = ""

                        results['license'] = ''
                        if jsondata['license']:
                            results['license'] = jsondata['license']

                        results['package_url'] = ''
                        if 'dist' in jsondata['current']:
                            if 'tarball' in jsondata['current']['dist']:
                                results['package_url'] = jsondata['current']['dist']['tarball']

                        results['nodeVersion'] = ''
                        if 'nodeVersion' in jsondata['current']:
                            results['nodeVersion'] = jsondata['current']['nodeVersion']

                        results['npmVersion'] = ''
                        if 'npmVersion' in jsondata['current']:
                            results['npmVersion'] = jsondata['current']['npmVersion']

                        results['summary'] = ''
                        if jsondata['description']:
                            results['summary'] = jsondata['description']

                        results['version'] = ''
                        if 'version' in jsondata['current']:
                            results['version'] = jsondata['current']['version']
                    
                else:
                    print("No local data found..")
                
                        

        elif echosystem == "java":
            package = package.replace(":","_")

            try:
                if "_" in package:
                    try:
                        groupId = package.split("_",1)[0]
                        print("ggg", groupId)
                        artifactId = package.split("_",1)[1]
                        print("aaa", artifactId)
                        packagepath = groupId.split('.',1)[1]
                        packagepath = packagepath.replace(".", "/")

                        url = "https://repo.maven.apache.org/maven2/%s/%s/%s/maven-metadata.xml" % (groupId.split('.',1)[0], packagepath, artifactId)
                        print(url)
                        data = requests.get(url)
                    
                        xpars = xmltodict.parse(data.text)
                        jsondata = json.dumps(xpars)
                        jsondata = json.loads(jsondata)
                    
                        versions_lists = jsondata['metadata']['versioning']['versions']['version']

                        version = jsondata['metadata']['versioning']['latest']

                        url = "https://repo.maven.apache.org/maven2/%s/%s/%s/%s/%s-%s.pom" % (groupId.split('.',1)[0], packagepath, artifactId, version, artifactId, version) 
                        print(url)
                        data = requests.get(url)
                        xpars = xmltodict.parse(data.text)
                        jsondata = json.dumps(xpars)

                        jsondata = json.loads(jsondata)

                        if "project" in jsondata and "version_lists" in jsondata["project"]:
                            jsondata["project"]["version_lists"] = []
                            for ver in versions_lists:
                                jsondata['project']['version_lists'].append(ver)

                        with open("/mnt/niahdb/packagesdb/maven/%s.json" % package, "w") as outfile:
                            json.dump(jsondata, outfile, indent=2)

                        if 'developers' in jsondata['project']:
                                if 'developer' in jsondata['project']['developers']:
                                    if 'name' in jsondata['project']['developers']['developer']:
                                        results['author'] = jsondata['project']['developers']['developer']['name']
                        else:
                            results['author'] = ''

                        results['groupId'] = ''
                        if 'groupId' in jsondata['project']:
                            results['groupId'] = jsondata['project']['groupId']

                        results['artifactId'] = ''
                        if 'artifactId' in jsondata['project']:
                            results['artifactId'] = jsondata['project']['artifactId']

                        results['description'] = ''
                        if 'description' in jsondata['project']:
                            results['description'] = jsondata['project']['description']

                        results['home_page'] = ''
                        if 'url' in jsondata['project']:
                            results['home_page'] = jsondata['project']['url']

                        results['license'] = ''
                        if 'licenses' in jsondata['project']:
                            if 'license' in jsondata['project']['licenses']:
                                if 'name' in jsondata['project']['licenses']['license']:
                                    results['license'] = jsondata['project']['licenses']['license']['name']

                        
                        if 'url' in jsondata['project']:
                            results['package_url'] = jsondata['project']['url']
                        else:
                            results['package_url'] = ''

                        results['requires_dist'] = ""
                        
                        results['requires_version'] = ''
                        if 'dependencies' in jsondata['project']:
                            if 'dependency' in jsondata['project']['dependencies']:
                                results['requires_version'] = jsondata['project']['dependencies']['dependency']
                        
                        results['summary'] = ""
                        results['version'] = ''
                        if 'version' in jsondata['project']:
                            results['version'] = jsondata['project']['version']
                        
                        results['releases'] = ''
                        if 'version_lists' in jsondata['project']:
                            results['releases'] = jsondata['project']['version_lists']

                        if check:
                            results = {}
                            results['author'] = ''
                            if 'developers' in jsondata['project']:
                                if 'developer' in jsondata['project']['developers']:
                                    if 'name' in jsondata['project']['developers']['developer']:
                                        results['author'] = jsondata['project']['developers']['developer']['name']
                            
                            results['groupId'] = ''
                            if 'groupId' in jsondata['project']:
                                results['groupId'] = jsondata['project']['groupId']
                            
                            results['artifactId'] = ''
                            if 'artifactId' in jsondata['project']:
                                results['artifactId'] = jsondata['project']['artifactId']
                            
                            results['home_page'] = ''
                            if 'url' in jsondata['project']:
                                results['home_page'] = jsondata['project']['url']

                            if 'licenses' in jsondata['project']:
                                if 'license' in jsondata['project']['licenses']:
                                    if 'name' in jsondata['project']['licenses']['license']:
                                        results['license'] = jsondata['project']['licenses']['license']['name']

                            results['package_url'] = ''
                            if 'url' in jsondata['project']:
                                results['package_url'] = jsondata['project']['url']
                            
                            results['summary'] = ''
                            if 'description' in jsondata['project']:
                                results['summary'] = jsondata['project']['description']
                            
                            results['version'] = ''
                            if 'version' in jsondata['project']:
                                results['version'] = jsondata['project']['version']

                        with open("/mnt/niahdb/packagesdb/maven/new/%s.json" % package, "r") as outfile:
                            json.dump(jsondata, outfile, indent=2)

                    except:
                        print("No live data found..")


            except:

                if os.path.isfile("/mnt/niahdb/packagesdb/maven/%s.json" % package):
                    print(package)
                    with open("/mnt/niahdb/packagesdb/maven/%s.json" % package, "r") as f:
                        jsondata = json.load(f)
                        print("checking from files")

                        if 'project' in jsondata:
                            if 'developers' in jsondata['project']:
                                        if 'developer' in jsondata['project']['developers']:
                                            if 'name' in jsondata['project']['developers']['developer']:
                                                results['author'] = jsondata['project']['developers']['developer']['name']
                            else:
                                results['author'] = ''

                            results['groupId'] = ''
                            if 'groupId' in jsondata['project']:
                                results['groupId'] = jsondata['project']['groupId']

                            results['artifactId'] = ''
                            if 'artifactId' in jsondata['project']:
                                results['artifactId'] = jsondata['project']['artifactId']

                            results['description'] = ''
                            if 'description' in jsondata['project']:
                                results['description'] = jsondata['project']['description']

                            results['home_page'] = ''
                            if 'url' in jsondata['project']:
                                results['home_page'] = jsondata['project']['url']

                            results['license'] = ''
                            if 'licenses' in jsondata['project']:
                                if 'license' in jsondata['project']['licenses']:
                                    if 'name' in jsondata['project']['licenses']['license']:
                                        results['license'] = jsondata['project']['licenses']['license']['name']

                            
                            if 'url' in jsondata['project']:
                                results['package_url'] = jsondata['project']['url']
                            else:
                                results['package_url'] = ''

                            results['requires_dist'] = ""
                            
                            results['requires_version'] = ''
                            if 'dependencies' in jsondata['project']:
                                if jsondata['project']['dependencies'] is not None:
                                    if 'dependency' in jsondata['project']['dependencies']:
                                        results['requires_version'] = jsondata['project']['dependencies']['dependency']
                                else:
                                    results['requires_version'] = ''

                            
                            results['summary'] = ""
                            results['version'] = ''
                            if 'version' in jsondata['project']:
                                results['version'] = jsondata['project']['version']
                            
                            results['releases'] = ''
                            if 'version_lists' in jsondata['project']:
                                results['releases'] = jsondata['project']['version_lists']

                            if check:
                                results = {}
                                results['author'] = ''
                                if 'developers' in jsondata['project']:
                                    if 'developer' in jsondata['project']['developers']:
                                        if 'name' in jsondata['project']['developers']['developer']:
                                            results['author'] = jsondata['project']['developers']['developer']['name']
                                
                                results['groupId'] = ''
                                if 'groupId' in jsondata['project']:
                                    results['groupId'] = jsondata['project']['groupId']
                                
                                results['artifactId'] = ''
                                if 'artifactId' in jsondata['project']:
                                    results['artifactId'] = jsondata['project']['artifactId']
                                
                                results['home_page'] = ''
                                if 'url' in jsondata['project']:
                                    results['home_page'] = jsondata['project']['url']

                                if 'licenses' in jsondata['project']:
                                    if 'license' in jsondata['project']['licenses']:
                                        if 'name' in jsondata['project']['licenses']['license']:
                                            results['license'] = jsondata['project']['licenses']['license']['name']

                                results['package_url'] = ''
                                if 'url' in jsondata['project']:
                                    results['package_url'] = jsondata['project']['url']
                                
                                results['summary'] = ''
                                if 'description' in jsondata['project']:
                                    results['summary'] = jsondata['project']['description']
                                
                                results['version'] = ''
                                if 'version' in jsondata['project']:
                                    results['version'] = jsondata['project']['version']

                        elif 'versions' in jsondata:
                            
                            if 'available_versions' in jsondata:
                                print("Available version present")
                                avail_version = jsondata['available_versions']
                                v = avail_version[-1]

                                print(v)
                                if v in jsondata['versions']:
                                    j_data = jsondata['versions'][v]

                                    results['author'] = ''

                                    results['home_page'] = ''

                                    results['license'] = ''

                                    results['description'] = ''
                                    if 'description' in j_data:
                                        results['description'] = j_data['description']

                                    results['latest_version'] = ''
                                    if 'version' in j_data:
                                        results['latest_version'] = j_data['version']
                                    
                                    results['releases'] = ''
                                    if 'available_versions' in jsondata:
                                        results['releases'] = jsondata['available_versions']

                                    if check:
                                        results = {}
                                        results['author'] = ''

                                        results['home_page'] = ''

                                        results['license'] = ''

                                        results['description'] = ''
                                        if 'description' in j_data:
                                            results['description'] = j_data['description']

                                        results['latest_version'] = ''
                                        if 'version' in j_data:
                                            results['version'] = j_data['version']
                                        
                                        results['releases'] = ''
                                        if 'available_versions' in jsondata:
                                            results['releases'] = jsondata['available_versions']


                            elif 'available_versions' not in jsondata:
                                if isinstance(jsondata['versions'], dict):
                                    j_data = list(jsondata['versions'].values())[0]
                                    print("Available version not present")
                                    release_list = jsondata['versions']
                                    
                                    
                                    results['author'] = ''
                                    if 'author' in j_data:
                                        if 'name' in j_data['author']:
                                            results['author'] = j_data['author']['name']

                                    results['home_page'] = ''

                                    results['license'] = ''
                                    if 'license' in j_data:
                                        results['license'] = j_data['license']

                                    results['description'] = ''
                                    if 'description' in j_data:
                                        results['description'] = j_data['description']

                                    results['latest_version'] = ''
                                    if 'version' in j_data:
                                        results['version'] = j_data['version']
                                    
                                    
                                    results['releases'] = list(release_list.keys())
                                    

                                    if check:
                                        results = {}
                                        results['author'] = ''
                                        if 'author' in j_data:
                                            if 'name' in j_data['author']:
                                                results['author'] = j_data['author']['name']

                                        results['home_page'] = ''

                                        results['license'] = ''
                                        if 'license' in j_data:
                                            results['license'] = j_data['license']

                                        results['description'] = ''
                                        if 'description' in j_data:
                                            results['description'] = j_data['description']

                                        results['latest_version'] = ''
                                        if 'version' in j_data:
                                            results['version'] = j_data['version']
                                        
                                        results['releases'] = list(release_list.keys())

                                else:
                                    results['author'] = ''
                                    results['home_page'] = jsondata['github_url']
                                    results['license'] = jsondata['license']

                                    results['description'] = ''
                                    if 'description' in jsondata:
                                        results['description'] = jsondata['description']
                                    results['latest_version'] = ''
                                    if 'latest_version' in jsondata:
                                        results['latest_version'] = jsondata['latest_version']
                                    
                                    results['releases'] = jsondata['versions']

                                    if check:
                                        results = {}
                                        results['author'] = ''
                                        results['home_page'] = jsondata['github_url']
                                        results['license'] = jsondata['license']

                                        results['description'] = ''
                                        if 'description' in jsondata:
                                            results['description'] = jsondata['description']
                                        results['latest_version'] = ''
                                        if 'latest_version' in jsondata:
                                            results['latest_version'] = jsondata['latest_version']
                                        
                                        results['releases'] = jsondata['versions']
                                    
                                    # print(results['releases'])


                else:
                    print("checking live data..")


        elif echosystem == "ruby":

            try:
                print("Checking live data..")
                url = 'https://rubygems.org/gems/%s' % package
                print(url)
                responce = requests.get(url)
                htmlContent = responce.content
                soup = BeautifulSoup(htmlContent, "html.parser")
            
                data = {}
                package = []
                
                pname = soup.find('div', class_='l-wrap--b').find('h1').text.strip().replace(" ","")
                p = pname.replace('\n\n', ',')
                package = p.split(",")
                p_name = package[0]
                latest_version = package[1]

                author = ''

                if soup.find('div', class_ = "l-overflow"):
                    if soup.find('div', class_ = "l-overflow").find('li', class_ = "gem__members"):
                        if soup.find('div', class_ = "l-overflow").find('li', class_ = "gem__members").find("ul", class_ = "t-list__items"):
                            authorsoup = soup.find('div', class_ = "l-overflow").find('li', class_ = "gem__members").find("ul", class_ = "t-list__items")
                            author = authorsoup.find('p').text.strip()
            
                p_dis = ''
                if soup.find('div', class_ = "gem__desc"):
                    if soup.find('div', class_ = "gem__desc").find('p'):
                        p_dis = soup.find('div', class_ = "gem__desc").find('p').text.strip()

                version_url = url + '/versions'
                r = requests.get(version_url)
                versionContent = r.content
                versionsoup = BeautifulSoup(versionContent, "html.parser")

                v_list = versionsoup.find('div', class_='versions')
                version_list =[]
                for a in v_list.findAll('li'):
                    a = a.find('a').text.strip()
                    version_list.append(a)

                license = ''
                if soup.find('div', class_="gem__aside l-col--r--pad"):
                    details_divs = soup.find('div', class_="gem__aside l-col--r--pad")
                    if details_divs.findAll('h2', class_="gem__ruby-version__heading t-list__heading"):
                        h2tags = details_divs.findAll('h2', class_="gem__ruby-version__heading t-list__heading")

                        for h2 in h2tags:
                            if 'License:' in h2.text:
                                license = h2.find('p').text.strip()

                r_dependencies = []
                try:
                    r_dep = soup.find('div', id='runtime_dependencies').find('div',class_='t-list__items')
                    for a in r_dep.findAll('li'):
                        r_dep1 = a.find('a').text.strip()
                        r_dependencies.append(r_dep1)
                except:
                    r_dependencies = []

                homeurl = ''
                try:
                    homeurl = soup.find('div',class_="gem__aside l-col--r--pad").find('div', class_='t-list__items').find('a', class_='gem__link t-list__item', id='home').get('href')
                except:
                    homeurl = ''
                
                results['package'] = p_name
                results['author'] = author
                results['description'] = p_dis
                results['HomeURL'] = homeurl
                results['license'] = license
                results['latest_version'] = latest_version
                results['package_url'] = ""
                results['Runtime_Dependencies'] = r_dependencies
                results['requires_version'] = ""
                results['summary'] = ""
                results['versions'] = ""

                if check:
                    results = {}
                    results['package'] = p_name
                    results['author'] = author
                    results['description'] = p_dis
                    results['HomeURL'] = homeurl
                    results['license'] = license
                    results['latest_version'] = latest_version
                    results['package_url'] = ""
                    results['Runtime_Dependencies'] = r_dependencies
                    results['requires_version'] = ""
                    results['summary'] = ""
                    results['versions'] = ""

                with open("/mnt/niahdb/packagesdb/ruby/%s.json" % p_name, "w") as outfile:  
                    json.dump(results, outfile, indent=2)


            except:

                if os.path.isfile("/mnt/niahdb/packagesdb/ruby/%s.json" % package):
                    with open("/mnt/niahdb/packagesdb/ruby/%s.json" % package, "r") as f:
                        jsondata = json.load(f)
                    
                    results['author'] = ""

                    results['description'] = ''
                    if jsondata['description']:
                        results['description'] = jsondata['description']
                        
                    results['home_page'] = ''
                    if 'HomeURL'in jsondata:
                        results['home_page'] = jsondata['HomeURL']
                    elif 'home_page' in jsondata:
                        results['home_page'] = jsondata['home_page']

                    results['license'] = ''
                    if jsondata['license']:
                        results['license'] = jsondata['license']

                    results['package_url'] = ''
                    if 'HomeURL'in jsondata:
                        results['package_url'] = jsondata['HomeURL']
                    elif 'home_page' in jsondata:
                        results['package_url'] = jsondata['home_page']

                    results['requires_dist'] = ''
                    if jsondata['Runtime_Dependencies']:
                        results['requires_dist'] = jsondata['Runtime_Dependencies']
                    
                    results['requires_version'] = ""
                    results['summary'] = ""

                    results['version'] = ''
                    if jsondata['latest_version']:
                        results['version'] = jsondata['latest_version']

                    results['releases'] = ''
                    if jsondata['versions']:
                        results['releases'] = jsondata['versions']

                    if check:
                        results = {}
                        results['author'] = ""

                        results['home_page'] = ''
                        if 'HomeURL'in jsondata:
                            results['home_page'] = jsondata['HomeURL']
                        elif 'home_page' in jsondata:
                            results['home_page'] = jsondata['home_page']

                        results['license'] = ''
                        if jsondata['license']:
                            results['license'] = jsondata['license']

                        results['package_url'] = ''
                        if 'HomeURL'in jsondata:
                            results['package_url'] = jsondata['HomeURL']
                        elif 'home_page' in jsondata:
                            results['package_url'] = jsondata['home_page']
                        
                        results['summary'] = ''
                        if jsondata['description']:
                            results['summary'] = jsondata['description']

                        results['version'] = ''
                        if jsondata['latest_version']:
                            results['version'] = jsondata['latest_version']

                else:
                    print("No local data found..")



        elif echosystem == "nuget":

            try:
                print("Checking live data..")
                url = 'https://www.nuget.org/packages/%s' % package
                r = requests.get(url)
                htmlContent = r.content
                soup = BeautifulSoup(htmlContent, "html.parser")
                data = {}
                

                latest_version = soup.find('div', class_='package-title').find('span', class_='version-title').text.strip()
            
                try:
                    p_dis = soup.find('div', id = "readme-tab").find('p').text.strip()
                except:
                    p_dis = ''

                v_list = soup.find('div', class_='version-history').find('tbody', class_='no-border')
                version_list =[]
                for a in v_list.findAll('tr'):
                    a = a.find('a').text.strip()
                    version_list.append(a)

                homepage = soup.find('ul', class_="list-unstyled ms-Icon-ul sidebar-links").findAll('li')[1].find('a').get('href')

                license = soup.find('ul', class_="list-unstyled ms-Icon-ul sidebar-links").findAll('li')[3].find('a').text.strip()

                require = soup.find('div', class_ = "package-header").find('p').text.strip()

                dependencies =[]
                try:
                    dep = soup.find('div', id ='dependencies-tab').find('ul', id ='dependency-groups')
                    for a in dep.findAll('a'):
                        dep1 = a.text.strip()
                        dependencies.append(dep1)
                except:
                    dependencies = []

               
                results['author'] = ""
                results['description'] = p_dis
                results['home_page'] = homepage
                results['license'] = license
                results['package_url'] = ''
                results['requires_dist'] = dependencies
                results['requires_version'] = require
                results['summary'] = ''
                results['version'] = latest_version
                results['releases'] = version_list

                if check:
                    results = {}
                    results['author'] = ""
                    results['description'] = p_dis
                    results['home_page'] = homepage
                    results['license'] = license
                    results['package_url'] = ''
                    results['requires_dist'] = dependencies
                    results['requires_version'] = require
                    results['summary'] = ''
                    results['version'] = latest_version
                    results['releases'] = version_list
                
                with open("/mnt/niahdb/packagesdb/nuget/%s.json" % package, "w") as outfile:
                        json.dump(results, outfile, indent=2)

                
            except:

                if os.path.isfile("/mnt/niahdb/packagesdb/nuget/%s.json" % package):
                    with open("/mnt/niahdb/packagesdb/nuget/%s.json" % package, "r") as f:
                        jsondata = json.load(f)

                    results['author'] = ""

                    results['description'] = ''
                    if jsondata['description']:
                        results['description'] = jsondata['description']

                    results['home_page'] = ''
                    if jsondata['Source-repo']:
                        results['home_page'] = jsondata['Source-repo']

                    results['license'] = ''
                    if jsondata['license']:
                        results['license'] = jsondata['license']

                    results['package_url'] = ''
                    if jsondata['project-website']:
                        results['package_url'] = jsondata['project-website']
                    
                    results['requires_dist'] = ''
                    if jsondata['Dependencies']:
                        results['requires_dist'] = jsondata['Dependencies']

                    results['requires_version'] = ""

                    results['summary'] = ''
                    if jsondata['summary']:
                        results['summary'] = jsondata['description']

                    results['version'] = ''
                    if jsondata['latest-version']:
                        results['version'] = jsondata['latest-version']

                    results['releases'] = ''
                    if jsondata['versions']:
                        results['releases'] = jsondata['versions']

                    if check:
                        results = {}
                        results['author'] = ""
                        
                        results['home_page'] = ''
                        if jsondata['Source-repo']:
                            results['home_page'] = jsondata['Source-repo']
                        
                        results['license'] = ''
                        if jsondata['license']:
                            results['license'] = jsondata['license']

                        results['package_url'] = ''
                        if jsondata['project-website']:
                            results['package_url'] = jsondata['project-website']

                        results['summary'] = ''
                        if jsondata['summary']:
                            results['summary'] = jsondata['description']

                        results['version'] = ''
                        if jsondata['latest-version']:
                            results['version'] = jsondata['latest-version']

                else:
                    print("No local data found..")
                


        elif echosystem == "rust":
            try:
                url = 'https://crates.io/api/v1/crates/%s' % package
                print(url)
                response = requests.get(url)
                jsondata  = response.json()

                if len(jsondata['versions']) > 0:
                        license = jsondata['versions'][0]['license']
                else:
                    license = ''

                results['author'] = ""
                results['description'] = ''
                if 'description' in jsondata['crate']:  
                    results['description'] = jsondata['crate']['description']

                results['home_page'] = ''
                if 'homepage' in jsondata['crate']: 
                    results['home_page'] = jsondata['crate']['homepage']
                
                results['license'] = license
                results['package_url'] = ''

                if 'repository' in jsondata['crate']:   
                    results['package_url'] = jsondata['crate']['repository']

                results['requires_dist'] = ''
                results['requires_version'] = ""
                results['summary'] = ""

                results['version'] = ''
                if 'newest_version' in jsondata['crate']:
                    results['version'] = jsondata['crate']['newest_version']
                
                results['releases'] = ''
                if jsondata['versions']:
                    results['releases'] = jsondata['versions']

                if check:
                    results = {}
                    results['author'] = ""
                    results['home_page'] = ''
                    if 'homepage' in jsondata['crate']: 
                        results['home_page'] = jsondata['crate']['homepage']

                    results['license'] = license

                    results['package_url'] = ''
                    if 'repository' in jsondata['crate']:
                        results['package_url'] = jsondata['crate']['repository']

                    results['summary'] = ''
                    if 'description' in jsondata['crate']:
                        results['summary'] = jsondata['crate']['description']
                    
                    results['version'] = ''
                    if 'newest_version' in jsondata['crate']:
                        results['version'] = jsondata['crate']['newest_version']

                with open("/mnt/niahdb/packagesdb/crates/%s.json" % package, "w") as outfile:
                    json.dump(jsondata, outfile, indent=2)

            except:
                if os.path.isfile("/mnt/niahdb/packagesdb/crates/%s.json" % package):
                    with open("/mnt/niahdb/packagesdb/crates/%s.json" % package, "r") as f:
                        jsondata = json.load(f)

                    if len(jsondata['versions']) > 0:
                        license = jsondata['versions'][0]['license']
                    else:
                        license = ''

                    results['author'] = ""

                    results['description'] = ''
                    if 'description' in jsondata['crate']:  
                        results['description'] = jsondata['crate']['description']

                    results['home_page'] = ''
                    if 'homepage' in jsondata['crate']: 
                        results['home_page'] = jsondata['crate']['homepage']
                    
                    results['license'] = license
                    results['package_url'] = ''

                    if 'repository' in jsondata['crate']:   
                        results['package_url'] = jsondata['crate']['repository']

                    results['requires_dist'] = ''
                    results['requires_version'] = ""
                    results['summary'] = ""

                    results['version'] = ''
                    if 'newest_version' in jsondata['crate']:
                        results['version'] = jsondata['crate']['newest_version']
                    
                    results['releases'] = ''
                    if jsondata['versions']:
                        results['releases'] = jsondata['versions']

                    if check:
                        results = {}
                        results['author'] = ""
                        results['home_page'] = ''
                        if 'homepage' in jsondata['crate']: 
                            results['home_page'] = jsondata['crate']['homepage']

                        results['license'] = license

                        results['package_url'] = ''
                        if 'repository' in jsondata['crate']:
                            results['package_url'] = jsondata['crate']['repository']

                        results['summary'] = ''
                        if 'description' in jsondata['crate']:
                            results['summary'] = jsondata['crate']['description']
                        
                        results['version'] = ''
                        if 'newest_version' in jsondata['crate']:
                            results['version'] = jsondata['crate']['newest_version']
                
                else:
                    print("No local data found..")


        elif echosystem == "elixir":
            try:
                print("Checking liva data...")
                url = 'https://hex.pm/packages/%s' % package
                r = requests.get(url)

                htmlContent = r.content
                soup = BeautifulSoup(htmlContent, "html.parser")

                version_url = url + '/versions'
                r1 = requests.get(version_url)
                versionContent = r1.content
                versionsoup = BeautifulSoup(versionContent, "html.parser")


                p_dis = ''
                if soup.find('div',class_ = "description with-divider"):
                    if soup.find('div',class_ = "description with-divider").find('p'):
                        p_dis = soup.find('div',class_ = "description with-divider").find('p').text
 
                if soup.find('span', class_="license"):
                    license = soup.find('span', class_="license").text
                else:
                    license = ''    
                
                versions = []
                vlist = versionsoup.find('div',class_ = 'version-list')
                if vlist:
                    li_elements = vlist.findAll('li')
                    if li_elements:
                        for a in li_elements:
                            ver = a.find('a').text.strip()
                            versions.append(ver)

                latest_version = ''
                version_element = soup.find('span', class_="version")
                if version_element is not None:
                    latest_version = version_element.text

                dependencies = []
                
                dep = None
                parent_div = soup.find('div', class_='col-md-9 no-padding')
                if parent_div is not None:
                    child_divs = parent_div.findAll('div', class_='col-md-11 with-divider no-padding')
                    if len(child_divs) >= 3:
                        dep = child_divs[2].findAll('div', class_='col-md-6 no-padding')[1]

                if dep is not None:
                    for a in dep.findAll('li'):
                        dep1 = a.find('a').text.strip()
                        dependencies.append(dep1)

                github_url = None
                div_col_md_9 = soup.find('div', class_='col-md-9 no-padding')
                if div_col_md_9:
                    github_url = div_col_md_9.find('div', class_='col-md-11 with-divider no-padding')

                if github_url:
                    if len(github_url.findAll('li')) > 1:
                        for anchor in github_url.findAll('li')[1]:
                            g_url = anchor.get('href')
                else:
                    g_url = ""


                results['author'] = ""
                results['description'] = p_dis
                results['home_page'] = g_url
                results['license'] = license
                results['package_url'] = g_url
                results['requires_dist'] = dependencies
                results['requires_version'] = ""
                results['summary'] = ""
                results['version'] = latest_version
                results['releases'] = versions

                if check:
                    results = {}
                    results['author'] = ""
                    results['description'] = p_dis
                    results['home_page'] = g_url
                    results['license'] = license
                    results['package_url'] = g_url
                    results['requires_dist'] = dependencies
                    results['requires_version'] = ""
                    results['summary'] = ""
                    results['version'] = latest_version
                    results['releases'] = versions
                
                with open("/mnt/niahdb/packagesdb/hex/%s.json" % package, "w") as outfile:
                        json.dump(results, outfile, indent=2)


            except:
                if os.path.isfile("/mnt/niahdb/packagesdb/hex/%s.json" % package):
                    with open("/mnt/niahdb/packagesdb/hex/%s.json" % package, "r") as f:
                        jsondata = json.load(f)

                    results['author'] = ""
                    results['description'] = ''
                    if jsondata['description']:
                        results['description'] = jsondata['description']

                    results['home_page'] = ''
                    if 'github_url' in jsondata:
                        results['home_page'] = jsondata['github_url']

                    results['license'] = ''
                    if jsondata['license']:
                        results['license'] = jsondata['license']
                    
                    results['package_url'] = ''
                    if 'github_url' in jsondata:
                        results['package_url'] = jsondata['github_url']

                    results['requires_dist'] = ''
                    if 'requires_dist' in jsondata:
                        results['requires_dist'] = jsondata['requires_dist']

                    results['requires_version'] = ""
                    results['summary'] = ""
                    
                    results['version'] = ''
                    try:
                        if jsondata['latest_version']:
                            results['version'] = jsondata['latest_version']
                    except:
                        if jsondata['version']:
                            results['version'] = jsondata['version']

                    results['releases'] = ''
                    try:
                        if jsondata['versions']:
                            results['releases'] = jsondata['versions']
                    except:
                        if jsondata['releases']:
                            results['releases'] = jsondata['releases']


                    if check:
                        results = {}
                        results['author'] = ""

                        results['home_page'] = ''
                        if 'github_url' in jsondata:
                            results['home_page'] = jsondata['github_url']

                        results['license'] = ''
                        if jsondata['license']:
                            results['license'] = jsondata['license']

                        results['package_url'] = ''
                        if 'github_url' in jsondata:
                            results['package_url'] = jsondata['github_url']

                        results['summary'] = ''
                        if jsondata['description']:
                            results['summary'] = jsondata['description']

                        results['version'] = ''
                        try:
                            if jsondata['latest_version']:
                                results['version'] = jsondata['latest_version']
                        except:
                            if jsondata['version']:
                                results['version'] = jsondata['version']

                else:
                    print("No local data found..")
                


        elif echosystem == "dart":
            try:
                print("Checking liva data...")
                url = 'https://pub.dev/packages/%s' % package

                page = requests.get(url)
                response = page.content
                soup = BeautifulSoup(response,"html.parser")
                version_url = url + '/versions'
                
                r = requests.get(version_url)
                versionContent = r.content
                versionsoup = BeautifulSoup(versionContent, "html.parser")

                versions = []
            
                vlist = versionsoup.find('table', class_ = 'version-table').find('tbody')

                for table in vlist.findAll('tr'):
                    ver = table.find('td').find('a').text
                    versions.append(ver)
                    
                l_version = versions[0]

                div = soup.find('div', class_ = 'detail-container').find('div', class_ = 'detail-tags')

                sdk_types = []
                if div.find('div', class_ = '-pub-tag-badge'):
                    sdk_type = div.find('div', class_ = '-pub-tag-badge').findAll('a')
                    for sdk in sdk_type:
                        sdk_types.append(sdk.text)

                
                description = soup.find('aside',class_ = 'detail-info-box').findAll("p")[1]
                des = description.text

                link = soup.find('aside',class_ = 'detail-info-box').findAll("p")[2]

                if link.find('a'):
                    home_url = link.find('a').get('href')
                    if 'github' in home_url:
                        git_link = home_url
                    else:
                        git_link = ''
                else:
                    home_url = ''
                    git_link = ''

                license = soup.find('aside',class_ = 'detail-info-box').findAll("p")[4]
                lic = license.text

                depends = []
                dependencies = soup.find('aside',class_ = 'detail-info-box').findAll("p")[5]

                dep_url = dependencies.findAll('a')
                for dep in dep_url:
                    if 'https' in dep.get('href'):
                        depends.append(dep.text)

                results['author'] = ""
                results['description'] = des
                results['home_page'] = home_url
                results['license'] = lic
                results['package_url'] = git_link
                results['requires_dist'] = depends
                results['requires_version'] = ""
                results['summary'] = ""
                results['version'] = l_version
                results['releases'] = versions


                if check:
                    results = {}
                    results['author'] = ""
                    results['description'] = des
                    results['home_page'] = home_url
                    results['license'] = lic
                    results['package_url'] = git_link
                    results['requires_dist'] = depends
                    results['requires_version'] = ""
                    results['summary'] = ""
                    results['version'] = l_version
                    results['releases'] = versions

                with open("/mnt/niahdb/packagesdb/pub_dev/%s.json" % package, "w") as outfile:
                    json.dump(results, outfile, indent=2)

            except:
                if os.path.isfile("/mnt/niahdb/packagesdb/pub_dev/%s.json" % package):
                    with open("/mnt/niahdb/packagesdb/pub_dev/%s.json" % package, "r") as f:
                        jsondata = json.load(f)

                    results['author'] = ""
                    results['description'] = ''
                    if jsondata['description']:
                        results['description'] = jsondata['description']

                    results['home_page'] = ''
                    if 'home_url' in jsondata:
                        results['home_page'] = jsondata['home_url']
                    elif 'home_page' in jsondata:
                        results['home_page'] = jsondata['home_page']

                    
                    results['license'] = ''
                    if jsondata['license']:
                        results['license'] = jsondata['license']
                    
                    results['package_url'] = ''
                    if 'github_url' in jsondata:
                        results['package_url'] = jsondata['github_url']

                    results['requires_dist'] = ''
                    if 'dependencies' in jsondata:    
                        results['requires_dist'] = jsondata['dependencies']
                    elif 'requires_dist' in jsondata:
                        results['requires_dist'] = jsondata['requires_dist']

                    results['requires_version'] = ""
                    results['summary'] = ""

                    results['version'] = ''
                    if 'latest_version' in jsondata:
                        results['version'] = jsondata['latest_version']
                    elif 'version' in jsondata:
                        results['version'] = jsondata['version']

                    results['releases'] = ''
                    try:
                        if jsondata['versions']:
                            results['releases'] = jsondata['versions']
                    except:
                        if jsondata['releases']:
                            results['releases'] = jsondata['releases']

                    if check:
                        results = {}
                        results['author'] = ""

                        results['home_page'] = ''
                        if 'home_url' in jsondata:
                            results['home_page'] = jsondata['home_url']
                        elif 'home_page' in jsondata:
                            results['home_page'] = jsondata['home_page']
                        
                        results['license'] = ''
                        if jsondata['license']:
                            results['license'] = jsondata['license']
                        
                        results['package_url'] = ''
                        if 'github_url' in jsondata:
                            results['package_url'] = jsondata['github_url']
                        
                        results['summary'] = ''
                        if jsondata['description']:
                            results['summary'] = jsondata['description']

                        results['version'] = ''
                        if 'latest_version' in jsondata:
                            results['version'] = jsondata['latest_version']
                        elif 'version' in jsondata:
                            results['version'] = jsondata['version']

                else:
                    print("Local data not found..")

        else:
            return False
        
        return results



    
    def get_package_license_details(self, product, echosystem):
        results = {}

        if echosystem == 'ubuntu':
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


        elif echosystem == 'debian':
            if os.path.isfile("/var/DB/license/debian_license_db.json"):
                with open("/var/DB/license/debian_license_db.json", "r") as f:
                    jsondata = json.load(f)

                jsondata = jsondata['results']

                jsondata = list(filter(lambda x: (product == x['name']), jsondata))
                
                if jsondata:
                    jsondata = jsondata[0]

                results['name'] = jsondata['name']
                results['license'] = jsondata['license']
                results['platform'] = jsondata['platform']
                results['version'] = jsondata['version']

                
        
        elif echosystem == 'java':
            try:
                print("Fetching from Live..")
                groupId = product.split(":",1)[0]
                artifactId = product.split(":",1)[1]
                packagepath = groupId.split('.',1)[1]
                packagepath = packagepath.replace(".", "/")

                url = "https://repo.maven.apache.org/maven2/%s/%s/%s/maven-metadata.xml" % (groupId.split('.',1)[0], packagepath, artifactId)
                        # print(url)
                data = requests.get(url)
                                    
                xpars = xmltodict.parse(data.text)
                jsondata = json.dumps(xpars)
                jsondata = json.loads(jsondata)

                versions_lists = jsondata['metadata']['versioning']['versions']['version']

                version = jsondata['metadata']['versioning']['latest']

                url = "https://repo.maven.apache.org/maven2/%s/%s/%s/%s/%s-%s.pom" % (groupId.split('.',1)[0], packagepath, artifactId, version, artifactId, version) 
                print(url)
                data = requests.get(url)
                xpars = xmltodict.parse(data.text)
                jsondata = json.dumps(xpars)

                jsondata = json.loads(jsondata)


                results['version'] = ''
                if 'version' in jsondata['project']:
                    results['version'] = jsondata['project']['version']

                results['installer'] = 'maven'
                results['name'] = ''
                if 'name' in jsondata['project']:
                    results['name'] = jsondata['project']['name']

                results['license'] = ''
                if 'licenses' in jsondata['project']:
                    if 'license' in jsondata['project']['licenses']:
                        if 'name' in jsondata['project']['licenses']['license']:
                            results['license'] = jsondata['project']['licenses']['license']['name']


            except:
                print("Fetching from local..")
                if os.path.isfile("/var/DB/license/maven_license_db.json"):
                    with open("/var/DB/license/maven_license_db.json", "r") as f:
                        jsondata = json.load(f)

                    jsondata = jsondata['results']

                    jsondata = list(filter(lambda x: (product == x['name']), jsondata))
                    
                    if jsondata:
                        jsondata = jsondata[0]

                    results['name'] = jsondata['name']
                    results['license'] = jsondata['license']
                    results['installer'] = 'maven'
                    results['version'] = jsondata['version']

                
        
        elif echosystem == 'javascript':
            try:
                print("Fetching from Live..")
                url = 'https://registry.npmjs.org/%s' % product
                print(url)
                response = urllib.request.urlopen(url)
                data = json.load(response)

                version = data['dist-tags']['latest']

                results['name'] = data['versions'][version]['name']
                results['license'] = data['versions'][version]['license']
                results['installer'] = 'npm'
                results['version'] = version
                

            except:
                print("Fetching from local..")
                if os.path.isfile("/var/DB/license/npm_license_db.json"):
                    with open("/var/DB/license/npm_license_db.json", "r") as f:
                        jsondata = json.load(f)

                    jsondata = jsondata['results']

                    jsondata = list(filter(lambda x: (product == x['name']), jsondata))
                    
                    if jsondata:
                        jsondata = jsondata[0]

                    results['name'] = jsondata['name']
                    results['license'] = jsondata['license']
                    results['installer'] = 'npm'
                    results['version'] = jsondata['version']

                
        
        elif echosystem == 'php':

            try:
                print("Fetching from Live..")
                url = 'https://repo.packagist.org/p2/%s.json' % product
                print(url)
                response = urllib.request.urlopen(url)
                data = json.load(response)

                results['name'] = data['packages'][product][0]['name']
                results['license'] = data['packages'][product][0]['license'][0]
                results['installer'] = 'composer'
                results['version'] = data['packages'][product][0]['version']

            except:
                print("Fetching from local..")
                if os.path.isfile("/var/DB/license/composer_license_db.json"):
                    with open("/var/DB/license/composer_license_db.json", "r") as f:
                        jsondata = json.load(f)

                    jsondata = jsondata['results']

                    jsondata = list(filter(lambda x: (product == x['name']), jsondata))
                    
                    if jsondata:
                        jsondata = jsondata[0]

                    results['name'] = jsondata['name']
                    results['license'] = jsondata['license']
                    results['installer'] = 'composer'
                    results['version'] = jsondata['version']

                
        
        elif echosystem == 'python':
            try:
                print("Fetching from Live..")
                url = 'https://pypi.org/pypi/%s/json' % product
                print(url)
                response = urllib.request.urlopen(url)
                data = json.load(response)

                results['name'] = data['info']['name']
                results['license'] = data['info']['license']
                results['installer'] = 'pypi'
                results['version'] = data['info']['version']
                # print(license)

            except:
                print("Fetching from local..")
                if os.path.isfile("/var/DB/license/pypi_license_db.json"):
                    with open("/var/DB/license/pypi_license_db.json", "r") as f:
                        jsondata = json.load(f)

                    jsondata = jsondata['results']

                    jsondata = list(filter(lambda x: (product == x['name']), jsondata))
                    
                    if jsondata:
                        jsondata = jsondata[0]

                    results['name'] = jsondata['name']
                    results['license'] = jsondata['license']
                    results['installer'] = 'pypi'
                    results['version'] = jsondata['version']

                
        return results
    

if __name__ == "__main__":
    res = get_json_feeds()

    years = '2022,2023'
    packages = ''
    echosystem = ''

    results = res.get_year(years)


    #results = res.get_packages(packages, echosystem)
    #results = res.get_echosystem_vuln(echosystem)

    with open("results.json", "w") as outfile:
        json.dump(results, outfile, indent=2)
