from unittest import result
from bs4 import BeautifulSoup
import xmltodict
import sqlite3
import requests
import re
import os
import sys
import configparser
import time
import datetime
import json
from tqdm import tqdm
sys.setrecursionlimit(50000)


class ubuntuParser():
    def __init__(self):
        self.daily = True
    
    def extract_copyright(self, link, target_dir):
        headers = requests.utils.default_headers()
        headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0',
        })

        page = requests.get(link, headers=headers)
        soup = BeautifulSoup(page.content, "html.parser")

        f = open("%s/copyright.txt" % target_dir, "w")
        f.write(str(soup))

    def extract_changelog(self, link, target_dir):
        headers = requests.utils.default_headers()
        headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0',
        })

        page = requests.get(link, headers=headers)
        soup = BeautifulSoup(page.content, "html.parser")

        f = open("%s/changelog.txt" % target_dir, "w")
        f.write(str(soup))

    def download(self, platform):
        cmd = "wget https://packages.ubuntu.com/%s/allpackages?format=txt.gz -O %s.gz" % (platform, platform)
        os.system(cmd)
        
        cmd = "gunzip %s.gz" % platform
        os.system(cmd)

    def rssfeed(self, platforms):
        for platform in platforms:
            try:
                target_dir = "/mnt/niahdb/packagesdb/platforms/ubuntu/%s" % platform
                if not os.path.isdir(target_dir):
                    os.system("mkdir %s" % target_dir)

                print("[ INFO ] %s platform rss fetching started" % platform)
                url = "https://packages.ubuntu.com/%s/main/newpkg?format=rss" % platform
                print("RSS - Link - %s" % url)
                headers = requests.utils.default_headers()
                headers.update({
                    'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0',
                })
                packages_list = []
                page = requests.get(url, headers=headers)
                results = xmltodict.parse(page.content)
                if 'item' in results['rdf:RDF']:
                    for item in tqdm(results['rdf:RDF']['item']):
                        link = item['link']
                        print("1 - %s" % link)
                        res = self.get_package(link, platform)
                        packagename = res['package']
                        packages_list.append(packagename)
            except:
                pass

            with open("/mnt/niahdb/niah-advisor/niah_pack/ubuntu_update.json", "w") as f:
                json.dump(packages_list, f, indent=2)

    def get_pkg_details(self, package, platform=None):
        results = {}

        if platform:
            link = "https://packages.ubuntu.com/%s/%s" % (platform, package)
            results[platform] = self.get_package(link, platform, package)
        else:
            link = "https://packages.ubuntu.com/"

            headers = requests.utils.default_headers()
            headers.update({
                'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0',
            })

            page = requests.get(link, headers=headers)
            soup = BeautifulSoup(page.content, "html.parser")

            platform_url = []

            contents_div = soup.findAll('div', {'id': 'content'})[0]
            uls = contents_div.findAll('ul')[0]
            for atag in uls.findAll('a'):
                platform = atag.text.strip()
                platform_url.append(platform)

            print("[ INFO ] Found %s platforms" % ','.join(platform_url))

            for platform in platform_url:
                link = "https://packages.ubuntu.com/%s/%s" % (platform, package)
                results[platform] = self.get_package(link, platform, package)

        return results

    def intialize(self):
        escape_arry = ['bionic', 'bionic-updates', 'bionic-backports', 'focal', 'focal-updates', 'focal-backports', 'impish', 'impish-updates', 'impish-backports', 'jammy']

        link = "https://packages.ubuntu.com/"

        headers = requests.utils.default_headers()
        headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0',
        })

        page = requests.get(link, headers=headers)
        soup = BeautifulSoup(page.content, "html.parser")

        platform_url = []

        contents_div = soup.findAll('div', {'id': 'content'})[0]
        uls = contents_div.findAll('ul')[0]
        for atag in uls.findAll('a'):
            platform = atag.text.strip()
            if platform not in escape_arry:
                platform_url.append(platform)

        print("[ INFO ] Found %s platforms" % ','.join(platform_url))

        print(platform_url)
        if self.daily:
            print("[ INFO ] Rss fetching")
            self.rssfeed(platform_url)

        if not self.daily:
            # print("Downloading platform data")
            #for platform in platform_url:
            #    self.download(platform)

            # Generating Packages json files
            #for platform in platform_url:
            #    with open("%s" % platform, "r") as f:
            #        packages_data = f.read()

            #    if re.findall(r'(.*?)\s\(.*\)\s', str(packages_data)):
            #        packages = re.findall(r'(.*?)\s\(.*\)\s', str(packages_data))

            #        print("Saving packages in file %s.json" % platform)
            #        with open("%s.json" % platform, 'w') as outfile:
            #            json.dump(packages, outfile)
            
            for platform in platform_url:
                target_dir = "/mnt/niahdb/packages/platforms/ubuntu/%s" % platform
                if not os.path.isdir(target_dir):
                    os.system("mkdir -p %s" % target_dir)

                with open("%s.json" % platform, "r") as f:
                    pkgjson = json.load(f)

                for package in pkgjson:
                    target_dir = '/mnt/niahdb/packages/platforms/ubuntu/%s/%s' % (platform, package)
                    if not os.path.isdir(target_dir):
                        link = "https://packages.ubuntu.com/%s/%s" % (platform, package)
                        print(link)
                        self.get_package(link, platform, package)


    def get_package(self, link, platform, packagename=False):
        print("Package - Url - %s" % link)
        headers = requests.utils.default_headers()
        headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0',
        })

        page = requests.get(link, headers=headers)
        soup = BeautifulSoup(page.content, "html.parser")
        
        if not packagename:
            packagename = re.findall(r'\/main\/(.*)', str(link))[0]

        description = ''
        try:
            if soup.findAll('div', {'id':'pdesc'}):
                desc_text = soup.findAll('div', {'id':'pdesc'})[0]
                description = desc_text.findAll('h2')[0].text
        except:
            pass

        packages = []
        if soup.findAll('div', {'id':'pdeps'}):
            dep_text = soup.findAll('div', {'id':'pdeps'})[0]
            dep_atags = dep_text.findAll('a')
            for dep in dep_atags:
                dep_pkg = dep.text
                packages.append(dep_pkg)

        dependencies = []
        if soup.findAll('ul', {'class':'uldep'}):
            if len(soup.findAll('ul', {'class':'uldep'})) > 1:
                uls = soup.findAll('ul', {'class':'uldep'})[1]
                for li in uls.findAll('li'):
                    if li.findAll('a'):
                        dep_pkg = li.findAll('a')[0].text
                        dependencies.append(dep_pkg)

        recommends = []
        if soup.findAll('ul', {'class':'ulrec'}):
            if len(soup.findAll('ul', {'class':'ulrec'})) > 1:
                uls = soup.findAll('ul', {'class':'ulrec'})[1]
                for li in uls.findAll('li'):
                    if li.findAll('a'):
                        rec_pkg = li.findAll('a')[0].text
                        recommends.append(rec_pkg)

        suggests = []
        if soup.findAll('ul', {'class':'ulsug'}):
            if len(soup.findAll('ul', {'class':'ulsug'})) > 1:
                uls = soup.findAll('ul', {'class':'ulsug'})[1]
                for li in uls.findAll('li'):
                    if li.findAll('a'):
                        sug_pkg = li.findAll('a')[0].text
                        suggests.append(sug_pkg)

        enhances = []
        if soup.findAll('ul', {'class':'ulenh'}):
            if len(soup.findAll('ul', {'class':'ulenh'})) > 1:
                uls = soup.findAll('ul', {'class':'ulenh'})[1]
                for li in uls.findAll('li'):
                    if li.findAll('a'):
                        enh_pkg = li.findAll('a')[0].text
                        enhances.append(enh_pkg)


        copyright_link = ''
        changelog_link = ''
        source_url = ''

        if soup.findAll('div', {'id':'pmoreinfo'}):
            moreinfo = soup.findAll('div', {'id':'pmoreinfo'})[0]
            for atag in moreinfo.findAll('a'):
                if atag.text.strip() == "Copyright File":
                    copyright_link = atag.get('href')
                if atag.text.strip() == "Ubuntu Changelog":
                    changelog_link = atag.get('href')
                if atag.text.strip() == "Homepage":
                    source_url = atag.get('href')


        pkg_version = ''
        h1txt = soup.findAll('h1')
        if re.findall(r'Package:\s+.*\s\((.*?)\s', str(h1txt)):
            pkg_version = re.findall(r'Package:\s+.*\s\((.*?)\s', str(h1txt))[0]
        elif re.findall(r'Package:\s+.*\s\((.*?)\)', str(h1txt)):
            pkg_version = re.findall(r'Package:\s+.*\s\((.*?)\)', str(h1txt))[0]

        res = {}
        res['package'] = packagename
        res['description'] = description
        res['packages'] = packages
        res['dependencies'] = dependencies
        res['recommends'] = recommends
        res['suggests'] = suggests
        res['enhances'] = enhances
        res['copyright_link'] = copyright_link
        res['changelog_link'] = changelog_link
        res['pkg_version'] = pkg_version
        res['source_url'] = source_url

        target_dir = '/mnt/niahdb/packages/platforms/ubuntu/%s/%s' % (platform, packagename)
        if os.path.isdir(target_dir):
            with open('%s/%s.json' % (target_dir, packagename)) as f:
                results = json.load(f)

            results['current'] = res
            results['versions'].append(res)
        else:
            os.system("mkdir -p %s" % target_dir)
            results = {}
            results['current'] = res
            results['versions'] = []
            results['versions'].append(res)

        if not os.path.exists("/tmp/lic_updates/ubuntu"):
            os.makedirs("/tmp/lic_updates/ubuntu")

        with open('%s/%s.json' % (target_dir, packagename), 'w') as outfile:
            json.dump(results, outfile, indent=2)


        with open("/tmp/lic_updates/ubuntu/%s.json" % packagename, "w") as outfile:
                json.dump(results, outfile, indent=2)
            
        if copyright_link:
            self.extract_copyright(copyright_link, target_dir)
        if changelog_link:
            self.extract_changelog(changelog_link, target_dir)

        return res

if __name__ == "__main__":
    now = datetime.datetime.now()
    date_update = "%s" % now.strftime("%Y-%m-%d %H:%M:%S")
    res = ubuntuParser()
    link = "https://packages.ubuntu.com/bionic/vim"
    res.intialize()
