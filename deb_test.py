from unittest import result
from bs4 import BeautifulSoup
import requests
import re
import os
import sys
import json
from tqdm import tqdm

platform = 'kinetic'
package = 'netkit-telnet'

url = "https://packages.ubuntu.com/%s/%s" % (platform, package)

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
