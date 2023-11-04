from bs4 import BeautifulSoup
import requests
import re
import json
import os
import sys
import datetime
import configparser
import time
import urllib
from tqdm import tqdm
import argparse
import os

__all__ = ["getstatusoutput","getoutput","getstatus"]

def getstatus(file):
    """Return output of "ls -ld <file>" in a string."""
    import warnings
    warnings.warn("commands.getstatus() is deprecated", DeprecationWarning, 2)
    return getoutput('ls -ld' + mkarg(file))

def getoutput(cmd):
    """Return output (stdout or stderr) of executing cmd in a shell."""
    return getstatusoutput(cmd)[1]

def getstatusoutput(cmd):
    """Return (status, output) of executing cmd in a shell."""
    import os
    pipe = os.popen('{ ' + cmd + '; } 2>&1', 'r')
    text = pipe.read()
    sts = pipe.close()
    if sts is None: sts = 0
    if text[-1:] == '\n': text = text[:-1]
    return sts, text

def mk2arg(head, x):
    import os
    return mkarg(os.path.join(head, x))

def mkarg(x):
    if '\'' not in x:
        return ' \'' + x + '\''
    s = ' "'
    for c in x:
        if c in '\\$"`':
            s = s + '\\'
        s = s + c
    s = s + '"'
    return s


class pypi_parser():
    def __init__(self):
        pass

    def get_stats_changes(self, packagename):
        results = {}
    
        cmd = "pypistats system urllib3 -f json"
        status, output = getstatusoutput(cmd)
        jsondata = eval(output)
        results['system'] = jsondata['data']

        results['days'] = []
        cmd = "pypistats recent urllib3 -f json"
        status, output = getstatusoutput(cmd)
        jsondata = eval(output)
        
        for k, v in jsondata['data'].items():
            res = {}
            res[k] = v
            results['days'].append(res)

        return results

    def git_actions(self, organization, name):
        headers = {
            'Accept': 'application/vnd.github+json',
            'Authorization': 'Bearer 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',
        }

        response = requests.get('https://api.github.com/orgs/%s/repos' % organization, headers=headers)
        jsondata = response.json()

        res = {}
        for data in jsondata:
            if name == data['name']:
                stargazers_count = data['stargazers_count']
                res['stargazers_count'] = stargazers_count
                forks = data['forks']
                res['forks'] = forks
                open_issues = data['open_issues']
                res['open_issues'] = open_issues
                watchers = data['watchers']
                res['watchers'] = watchers
                visibility = data['visibility']
                res['visibility'] = visibility
                contributors_res = requests.get('%s' % data['contributors_url'], headers=headers)
                contributors = contributors_res.json()
                res['contributors'] = contributors

        os.chdir("/tmp")
        cmd = "rm -rf %s" % name
        cmd = "git clone https://github.com/%s/%s.git" % (organization, name)
        status, output = getstatusoutput(cmd)

        if os.path.isfile("%s/CODE_OF_CONDUCT.md" % name):
            res['CODE_OF_CONDUCT.md'] = "yes"
        else:
            res['CODE_OF_CONDUCT.md'] = "no"
        
        if os.path.isfile("%s/README.md" % name):
            res['README.md'] = "yes"
        else:
            res['README.md'] = "no"

        if len(contributors) > 0:
            res['CONTRIBUTORS'] = "yes"
        else:
            res['CONTRIBUTORS'] = "no"

        return res

    def pypi_parser_by_package(self, packagename):
        url = "https://pypi.org/pypi/%s/json" % packagename
        response = urllib.request.urlopen(url)
        data = json.load(response)
        info = data['info']

        results = {}
        results['header1'] = {}
        results['header1']['summary'] = info['summary']
        results['header1']['name'] = info['name']
        results['header1']['installation'] = "pip install %s" % packagename
        results['header1']['license'] = info['license']
        results['header1']['version'] = info['version']
        results['header1']['package_url'] = info['package_url']
        results['header1']['code_url'] = info['project_urls']['Code']
        results['header1']['homepage'] = info['project_urls']['Homepage']
        results['header1']['author'] = info['author']
        results['header1']['author_email'] = info['author_email']

        if re.findall(r'https:\/\/github\.com\/(.*)\/(.*)', str(info['project_urls']['Code'])):
            organization = re.findall(r'https:\/\/github\.com\/(.*)\/(.*)', str(info['project_urls']['Code']))[0][0]
            name = re.findall(r'https:\/\/github\.com\/(.*)\/(.*)', str(info['project_urls']['Code']))[0][1]
            git_details = self.git_actions(organization, name)
        else:
            git_details = False

        results['header2'] = {}
        results['header2']['security'] = "NONE"
        results['header2']['popularity'] = "NONE"
        results['header2']['maintenance'] = "NONE"
        results['header2']['community'] = "NONE"
        results['header2']['score'] = "80"
        results['header2']['outof'] = "100"
        results['header2']['text'] = "Package Health Score"

        results['div1'] = {}
        results['div1']['text'] = "Package Metadata"
        results['div1']['keywords'] = info['keywords']
        results['div1']['dependencies'] = info['requires_dist']
        results['div1']['requires_python'] = info['requires_python']
        results['div1']['classifiers'] = info['classifiers']

        results['div2'] = {}
        results['div2']['text'] = "Package Releases"
        results['div2']['versions'] = data['releases']

        results['div3'] = {}
        results['div3']['text'] = "Popularity"
        results['div3']['charts'] = {}
        popularity = self.get_stats_changes(packagename)
        results['div3']['charts']['chart1'] = {}
        results['div3']['charts']['chart1']['text'] = "System Wise Download"
        results['div3']['charts']['chart1']['system'] = popularity['system']
        results['div3']['charts']['chart2'] = {}
        results['div3']['charts']['chart2']['text'] = "Days Wise Download"
        results['div3']['charts']['chart2']['days'] = popularity['days']
        results['div3']['details'] = {}
        if git_details:
            results['div3']['details']['forks'] = git_details['forks']
            results['div3']['details']['contributors'] = git_details['contributors']
            results['div3']['details']['watchers'] = git_details['watchers']
            results['div3']['details']['stargazers_count'] = git_details['stargazers_count']

        popularity = self.get_stats_changes(packagename)

        results['div4'] = {}
        results['div4']['text'] = "Maintenance"
        results['div4']['charts'] = {}
        results['div4']['charts']['chart1'] = {}
        results['div4']['charts']['chart1']['text'] = "System Wise Download"
        results['div4']['charts']['chart1']['system'] = popularity['system']
        results['div4']['details'] = {}
        if git_details:
            results['div4']['details']['open_issues'] = git_details['open_issues']
        results['div4']['details']['releases'] = len(data['releases'])
        results['div4']['details']['last_releases'] = data['releases'][info['version']][0]['upload_time']

        results['div5'] = {}
        results['div5']['text'] = "Community"
        results['div5']['details'] = {}
        if git_details:
            results['div5']['details']['CODE_OF_CONDUCT.md'] = git_details['CODE_OF_CONDUCT.md']
            results['div5']['details']['README.md'] = git_details['README.md']
            results['div5']['details']['CONTRIBUTORS'] = git_details['CONTRIBUTORS']

        return results

    def pypiParser(self, url_name, url):
        try:
            response = urllib.request.urlopen(url)
            data = json.load(response)

            dirName = url_name
         
            with open("/var/DB/packages/pypi/%s.json" % dirName, "w") as outfile:
                json.dump(data, outfile)
        except:
            print(f"HTTPError: HTTP Error 404: Not Found : {url}")


    def startParsing(self, fullscan):
        if fullscan == "yes":
            if not os.path.exists('pypi_data.json'):
                url = "https://pypi.org/simple/"
                jsonData = []
                page = requests.get(url).text
                soup = BeautifulSoup(page, "html.parser")
                a_elements = soup.findAll("a")
                for a_tag in a_elements:
                    jsonData.append(a_tag.text)

                with open("pypi_data.json", "w") as f:
                    json.dump(jsonData, f, indent=4)

            with open("pypi_data.json", "r") as f:
                out_data = json.load(f)

            i = 0
            for tagname in tqdm(out_data):
                url = f"https://pypi.org/pypi/{tagname}/json";
                self.pypiParser(tagname, url)
        else:
            urls = ["https://pypi.org/rss/updates.xml", "https://pypi.org/rss/packages.xml"]
            for url in urls:
                daily_items = []
                page = requests.get(url).text
                soup = BeautifulSoup(page, "html.parser")
                item_elements = soup.findAll("item")
                for item_tag in item_elements:
                    title_tag = item_tag.find("title")
                    daily_items.append(title_tag.text.split(" ")[0])

                with open("pypi_daily_data.json", "w") as f:
                    json.dump(daily_items, f, indent=2)

                with open("pypi_daily_data.json", "r") as f:
                    daily_data = json.load(f)

                process_json = {}
            

                for item in tqdm(daily_data):
                    url = f"https://pypi.org/pypi/{item}/json";
                    self.pypiParser(item, url)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-s', '--scan', type=str,  help='enter scan full/daily')
    results = parser.parse_args()

    print(" [ OK ] Scan Started")
    res = pypi_parser()
    #res.pypi_parser_by_package("urllib3")
    results = res.pypi_parser_by_package("urllib3")
    print(results)
    #res.startParsing(results.scan)
    #print("Scan Complete")
   