import time
from unittest.mock import patch
import warnings
from xml.dom import HierarchyRequestErr
import glob2
from github import Github
import os
import pyfiglet
from os import path
import random
import semantic_version
import ast
import sys
import re
import requests
from pkg_resources import parse_version
import json
import argparse
from tqdm import tqdm
from datetime import datetime
from prettytable import PrettyTable
from termcolor import colored
import socket
from pyfiglet import figlet_format
import platform
import requirements


home_directory_default = os.path.expanduser( '~' )

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


class niah_scanner_sbom():
    def __init__(self):
        pass

    def gtEq(self, vers1, mVers):
        if parse_version(mVers) >= parse_version(vers1):
            return True
        else:
            return False

    def gt(self, vers1, mVers):
        if parse_version(mVers) > parse_version(vers1):
            return True
        else:
            return False

    def ltEq(self, vers1, mVers):
        if parse_version(mVers) <= parse_version(vers1):
            return True
        else:
            return False

    def lt(self, vers1, mVers):
        if parse_version(mVers) < parse_version(vers1):
            return True
        else:
            return False

    def eq(self, vers1, mVers):
        if parse_version(mVers) == parse_version(vers1):
            return True
        else:
            return False

    def getUnique(self, lists):
        unique_list = [] 
        for x in lists:
                if x not in unique_list:
                        unique_list.append(x)
        return unique_list

    def ubuntu_compare(self, ver1, ver2):
        import apt_pkg
        apt_pkg.init_system()
        print("1 - %s" % ver1)
        print("2 - %s" % ver2)
        vc=apt_pkg.version_compare(ver1, ver2)

        if vc > 0:
            return True
        elif vc == 0:
            return True
        elif vc < 0:
            return False


    def vuln_parser(self, ecosystem_vulnerability_db, inventory):
        issues = []
        pkg_counts = []
        vuln_found = []
        vuln_pkg_counts = []
        severities = {}

        for inv in tqdm(inventory):
            name = inv['name']

            if name in pkg_counts:
                pkg_counts.append(name)

            in_version = inv['version']
            s_type = inv['type']
            bom_ref = inv['bom-ref']
            cpe = inv['cpe']
            purl = inv['purl']
            license = inv['license']
            vuln_db = list(filter(lambda x: (name == x['package']), ecosystem_vulnerability_db['db']))

            if ecosystem_vulnerability_db['ecosystem'] == "ubuntu" or ecosystem_vulnerability_db['ecosystem'] == "debian":
                for vuln in vuln_db:
                    version = vuln['versions']
                    published = vuln['published']
                    severity = vuln['severity']
                    cves = ','.join(vuln['cves'])
                    niah_id = vuln['niah_id']
                    osname = vuln['osname']
                    advisory_id = vuln['id']
                    if 'cwes_id' in vuln:
                        cwes_id = ','.join(vuln['cwes_id'])
                    else:
                        cwes_id = ''

                    res = {}
                    res['package'] = name
                    res['installed_version'] = in_version
                    res['cves'] = cves
                    res['niah_id'] = niah_id
                    res['osname'] = osname
                    res['severity'] = severity
                    res['published'] = published
                    res['patch'] = "Upgrade version %s" % version
                    res['cpe'] = cpe
                    res['bom-ref'] = bom_ref
                    res['purl'] = purl
                    res['license'] = license
                    res['type'] = s_type
                    res['cwe_text'] = cwes_id
                    res['advisory_id'] = advisory_id
                    
                    if ecosystem_vulnerability_db['ecosystem'] == "ubuntu":
                        if self.ubuntu_compare(in_version, version):
                            issues.append(res)

                            if name not in vuln_pkg_counts:
                                vuln_pkg_counts.append(name)

                            if res not in vuln_found:
                                vuln_found.append(res)
                            
                            if severity.upper() not in severities:
                                severities[severity.upper()] = []

                            if res not in severities[severity.upper()]:
                                severities[severity.upper()].append(res)
            else:
                for vuln in vuln_db:
                    language = vuln['language']
                    installer = vuln['installer']
                    refeid = vuln['refeid']
                    summary = vuln['summary']
                    published = vuln['published']
                    severity = vuln['severity']
                    cvssv3 = vuln['cvssv3']
                    niah_id = vuln['niah_id']
                    cves = ','.join(vuln['cves'])
                    versions = vuln['versions']
                    if 'cwes_id' in vuln:
                        cwes_id = ','.join(vuln['cwes_id'])
                    else:
                        cwes_id = ''

                    res = {}
                    res['package'] = name
                    res['installed_version'] = in_version
                    res['cves'] = cves
                    res['niah_id'] = niah_id
                    res['severity'] = severity
                    res['published'] = published
                    res['cpe'] = cpe
                    res['bom-ref'] = bom_ref
                    res['purl'] = purl
                    res['license'] = license
                    res['type'] = s_type
                    res['cwe_text'] = cwes_id

                    for vers in versions:
                        if re.findall(r'\[.*:.*\]', str(vers)):
                            vers1 = re.findall(r'\[(.*):', str(vers))[0]
                            vers2 = re.findall(r':(.*)\]', str(vers))[0]
                            res['patch'] = "Upgrade version %s" % vers2

                            if self.gtEq(vers1, in_version) and self.ltEq(vers2, in_version):
                                issues.append(res)

                                if name not in vuln_pkg_counts:
                                    vuln_pkg_counts.append(name)
                                
                                if res not in vuln_found:
                                    vuln_found.append(res)

                                if severity.upper() not in severities:
                                    severities[severity.upper()] = []

                                if res not in severities[severity.upper()]:
                                    severities[severity.upper()].append(res)

                        elif re.findall(r'\(.*:.*\]', str(vers)):
                            vers1 = re.findall(r'\((.*):', str(vers))[0]
                            vers2 = re.findall(r':(.*)\]', str(vers))[0]
                            res['patch'] = "Upgrade version %s" % vers2

                            if self.gt(vers1, in_version) and self.ltEq(vers2, in_version):
                                issues.append(res)

                                if name not in vuln_pkg_counts:
                                    vuln_pkg_counts.append(name)

                                if res not in vuln_found:
                                    vuln_found.append(res)

                                if severity.upper() not in severities:
                                    severities[severity.upper()] = []

                                if res not in severities[severity.upper()]:
                                    severities[severity.upper()].append(res)

                        elif re.findall(r'\[.*:.*\)', str(vers)):
                            vers1 = re.findall(r'\[(.*):', str(vers))[0]
                            vers2 = re.findall(r':(.*)\)', str(vers))[0]
                            res['patch'] = "Upgrade latest version after %s" % vers2

                            if self.gtEq(vers1, in_version) and self.lt(vers2, in_version):                                
                                issues.append(res)

                                if name not in vuln_pkg_counts:
                                    vuln_pkg_counts.append(name)
                                
                                if res not in vuln_found:
                                    vuln_found.append(res)

                                if severity.upper() not in severities:
                                    severities[severity.upper()] = []

                                if res not in severities[severity.upper()]:
                                    severities[severity.upper()].append(res)

                        elif re.findall(r'\(.*:.*\)', str(vers)):
                            vers1 = re.findall(r'\((.*):', str(vers))[0]
                            vers2 = re.findall(r':(.*)\)', str(vers))[0]
                            res['patch'] = "Upgrade latest version after %s" % vers2

                            if self.gt(vers1, in_version) and self.lt(vers2, in_version):
                                issues.append(res)

                                if name not in vuln_pkg_counts:
                                    vuln_pkg_counts.append(name)
                                
                                if res not in vuln_found:
                                    vuln_found.append(res)

                                if severity.upper() not in severities:
                                    severities[severity.upper()] = []

                                if res not in severities[severity.upper()]:
                                    severities[severity.upper()].append(res)

                        elif re.findall(r'\(.*:.*\)', str(vers)):
                            vers1 = re.findall(r'\((.*):', str(vers))[0]
                            vers2 = re.findall(r':(.*)\)', str(vers))[0]
                            res['patch'] = "Upgrade latest version after %s" % vers2

                            if self.gt(vers1, in_version) and self.lt(vers2, in_version):
                                issues.append(res)

                                if name not in vuln_pkg_counts:
                                    vuln_pkg_counts.append(name)
                                
                                if res not in vuln_found:
                                    vuln_found.append(res)

                                if severity.upper() not in severities:
                                    severities[severity.upper()] = []

                                if res not in severities[severity.upper()]:
                                    severities[severity.upper()].append(res)

                        else:
                            vers1 = str(vers)
                            res['patch'] = "Upgrade latest version after %s" % vers2
                            if self.eq(vers1, in_version):
                                issues.append(res)

                                if name not in vuln_pkg_counts:
                                    vuln_pkg_counts.append(name)
                                
                                if res not in vuln_found:
                                    vuln_found.append(res)
                                
                                if severity.upper() not in severities:
                                    severities[severity.upper()] = []

                                if res not in severities[severity.upper()]:
                                    severities[severity.upper()].append(res)

        results = {}
        results['issues'] = issues
        results['pkg_counts'] = pkg_counts
        results['vuln_found'] = vuln_found
        results['vuln_pkg_counts'] = vuln_pkg_counts
        results['severities'] = severities

        return results
    
    def syncData(self, ecosystem):
        print(ecosystem)

        filename = "%s.json" % ecosystem
        
        # ecosystems = ['c#', 'c', 'dart', 'elixir', 'go', 'java', 'javascript', 'php', 'python', 'ruby', 'rust']
        # ecosystem_platforms = ['ubuntu', 'debian', 'rhel', 'oracle_linux']
        # unknown_vulns = ['noncve']
        
        # if ecosystem not in ecosystem_platforms and ecosystem not in ecosystems and ecosystem not in unknown_vulns:
        #     results['error'] = "ecosystem not supported"
        #     return results

        # if ecosystem in ecosystems:
        #     eco_type = "dependencies"
        
        # if ecosystem in ecosystem_platforms:
        #     eco_type = "platform"

        # if ecosystem in unknown_vulns:
        #     eco_type = "noncve"

        # if eco_type == "dependencies":

        results = {}
        results['data'] = []
        
        for dep_file in os.listdir("/var/DB/feeds/language/"):
            if filename == dep_file:
                with open("/var/DB/feeds/language/%s" % filename, "r") as f:
                    jsondata1 = json.load(f)
                
                jsondata1['results'].sort(key=lambda x: x["modified"], reverse=True)
                jsondata1 = jsondata1['results']
                
                #with open("/var/DB/feeds/non-cve/noncve_feed.json", "r") as f:
                #    jsondata2 = json.load(f)
                
                #jsondata2 = jsondata2['results']

                #jsondata2 = list(filter(lambda x:(ecosystem == x['language']),jsondata2))
                #jsondata = jsondata1 + jsondata2
                jsondata = jsondata1
                
                results['data'] = jsondata
    
        return results


    def get_license_key(self, api_key, ip):
        headers = {
            'Content-Type': 'application/json',
        }

        json_data = {
            'apikey': '%s' % api_key,
        }
        
        print(ip)
        response = requests.post('http://%s:9182/api/v1/get/license/key' % ip , headers=headers, json=json_data)
        data = response.json()

        print("license_key", data)

        if 'api_key' in data:
            license_key = data['api_key']
            return license_key
        else:
            print("[ OK ] Error in fetching API Key")
            sys.exist(1)


    def get_profile(self, api_key, ip):
        headers = {
            'Content-Type': 'application/json',
        }

        json_data = {
            'apikey': '%s' % api_key,
        }
        print("jjjj",json_data)
        response = requests.post('http://%s:9182/api/v1/scan/profile' % ip, headers=headers, json=json_data)


        print("rrrr",response)

        return response.json()
    
    def get_profile_scanid(self, api_key, scanid, ip):
        headers = {
            'Content-Type': 'application/json',
        }

        json_data = {
            'apikey': '%s' % api_key,
            'scanid': '%s' % scanid,
        }

        response = requests.post('http://%s:9182/api/v1/scan/detail' % ip, headers=headers, json=json_data)
        return response.json()
    
    def get_profile_projectid(self, api_key, projectid, ip):
        headers = {
            'Content-Type': 'application/json',
        }

        json_data = {
            'apikey': '%s' % api_key,
            'projectid': '%s' % projectid,
        }

        response = requests.post('http://%s:9182/api/v1/project/detail' % ip, headers=headers, json=json_data)
        print("rrrrr", response)
        
        return response.json()
    
    def get_inventory(self, sbomdata):
        inventory = []

        for component in sbomdata['components']:
            name = component['name']
            if 'version' in component:
                version = component['version']
            else:
                version = ''
            s_type = component['type']
            bom_ref = ''
            if 'bom-ref' in component:
                bom_ref = component['bom-ref']
            license = ''
            if 'licenses' in component:
                if len(component['licenses']) > 0:
                    if 'license' in component['licenses'][0]:
                        if 'id' in component['licenses'][0]['license']:
                            license = component['licenses'][0]['license']['id']
                        elif 'name' in component['licenses'][0]['license']:
                            license = component['licenses'][0]['license']['name']
                        else:
                            license = ''

            cpe = ''
            if 'cpe' in component:
                cpe = component['cpe']
            purl = ''
            if 'purl' in component:
                purl = component['purl']

            if version:
                res = {}
                res['name'] = name
                res['version'] = version
                res['type'] = s_type
                res['bom-ref'] = bom_ref
                res['cpe'] = cpe
                res['purl'] = purl
                res['license'] = license

                inventory.append(res)

        return inventory

    def scan_with_projectid(self, api_key, projectid, sbomdata, report_path, scanner_type, tags, scan_details, ip):
        now = datetime.now()
        report_name = now.strftime("%d-%m-%Y_%H:%M:%S")

        profile = self.get_profile_projectid(api_key, projectid, ip)

        profile['scan_details'] = scan_details
        profile['scanner_type'] = scanner_type
        profile['source'] = 'sbom'
        profile['tags'] = tags
        profile['api_key'] = api_key


        results = self.scan_bom(profile, sbomdata, api_key, ip)
        results['header']['Date'] = report_name
        print(results)

        with open("%s/%s.json" % (report_path, report_name), "w") as f:
            json.dump(results, f, indent=2)

        print("[ INFO ] Vulnerabilities Report ready - %s/%s.json" % (report_path, report_name))

        headers = {
            'Content-Type': 'application/json',
        }
        
        files = [
            ('file', ("%s.json" % report_name, open("/home/niah/%s.json" % report_name, 'rb'), 'application/octet')),
            ('data', ('data', json.dumps(profile), 'application/json')),
        ]

        url = 'http://%s:9182/api/report-upload' % (ip)
        print(url)
        response = requests.post(url, files=files)
        print("Response - %s" % response.text)
        print(response.status_code)

        if response.status_code == 201:
            print("[ INFO ] Report %s uloaded on server" % report_name)
        elif response.status_code == 400:
            print("[ INFO ] User does not exists")
        elif response.status_code == 401:
            print("[ INFO ] Report %s already exist on server" % report_name)
        else:
            print("[ ERROR ] Report %s Upload Error" % report_name)
            
    def scan_with_scanid(self, api_key, scanid, sbomdata, tags, report_path, ip):
        now = datetime.now()
        report_name = now.strftime("%d-%m-%Y_%H:%M:%S")

        profile = self.get_profile_scanid(api_key, scanid, ip)
        profile['tags'] = tags
        profile['api_key'] = api_key
        
        results = self.scan_bom(profile, sbomdata, api_key, ip)
        results['header']['Date'] = report_name
        print(results)

        with open("%s/%s.json" % (report_path, report_name), "w") as f:
            json.dump(results, f, indent=2)

        print("[ INFO ] Vulnerabilities Report ready - %s/%s.json" % (report_path, report_name))

        headers = {
            'Content-Type': 'application/json',
        }
        
        files = [
            ('file', ("%s.json" % report_name, open("/home/niah/%s.json" % report_name, 'rb'), 'application/octet')),
            ('data', ('data', json.dumps(profile), 'application/json')),
        ]

        url = 'http://%s:9182/api/report-upload' % (ip)
        response = requests.post(url, files=files)
        print("Response - %s" % response.text)

        if response.status_code == 201:
            print("[ INFO ] Report %s uploaded on server" % report_name)
        elif response.status_code == 400:
            print("[ INFO ] User does not exists")
        elif response.status_code == 401:
            print("[ INFO ] Report %s already exist on server" % report_name)
        else:
            print("[ ERROR ] Report %s Upload Error" % report_name)


    def scan_default(self, api_key, name, scanner_type, tags, scan_details, docker, report_path, ip):
        now = datetime.now()
        report_name = now.strftime("%d-%m-%Y_%H:%M:%S")

        profile = self.get_profile(api_key, ip)

        profile['name'] = name
        profile['connname'] = 'sbom'
        profile['docker'] = docker
        profile['project_details'] = {}
        profile['scan_details'] = scan_details
        profile['scanner_type'] = scanner_type
        profile['source'] = 'sbom'
        profile['tags'] = tags
        profile['api_key'] = api_key

        results = self.scan_bom(profile, sbomdata, api_key, ip)
        results['header']['Date'] = report_name

        print("11111","%s/%s.json" % (report_path, report_name))

        with open("%s/%s.json" % (report_path, report_name), "w") as f:
            json.dump(results, f, indent=2)

        print("[ INFO ] Vulnerabilities Report ready - %s/%s.json" % (report_path, report_name))

        headers = {
            'Content-Type': 'application/json',
        }
        print(os.getcwd())

        print("Report_path", report_path)
        print("Report_name", report_name)

        report_file_path = "%s/%s.json" % (report_path, report_name)

        print("====",report_file_path)
        print(profile)

        files = [
            ('file', ("%s.json" % report_name, open("/home/niah/%s.json" % report_name, 'rb'), 'application/octet')),
            ('data', ('data', json.dumps(profile), 'application/json')),
        ]

        print(files)

        url = 'http://%s:9182/api/report-upload' % (ip)
        print(url)
        response = requests.post(url, files=files)
        print("Response - %s" % response.text)
        print(response.status_code)

        if response.status_code == 201:
            print("[ INFO ] Report %s uloaded on server" % report_name)
        elif response.status_code == 200:
            print("[ INFO ] Report %s uloaded on server" % report_name)
        elif response.status_code == 400:
            print("[ INFO ] User does not exists")
        elif response.status_code == 401:
            print("[ INFO ] Report %s already exist on server" % report_name)
        else:
            print("[ ERROR ] Report %s Upload Error" % report_name)

    def scan_bom(self, sbomdata, ecosystem):
        projectid = ''
        scanid = ''

        # if 'name' in profile:
        #     name = profile['name']
        # if 'company_id' in profile:
        #     company_id = profile['company_id']
        # if 'team_id' in profile:
        #     team_id = profile['team_id']
        # if 'connname' in profile:
        #     connname = profile['connname']
        # if 'docker' in profile:
        #     docker = profile['docker']
        # if 'project_details' in profile:
        #     project_details = profile['project_details']
        # if 'projectid' in profile:
        #     projectid = profile['projectid']
        # if 'publishdate' in profile:
        #     publishdate = profile['publishdate']
        # if 'updatedate' in profile:
        #     updatedate = profile['updatedate']
        # if 'scan_details' in profile:
        #     scan_details = profile['scan_details']
        # if 'project_details' in profile:
        #     project_details = profile['project_details']
        # if 'scanid' in profile:
        #     scanid = profile['scanid']
        # if 'scanner_type' in profile:
        #     scanner_type = profile['scanner_type']
        # if 'source' in profile:
        #     source = profile['source']
        # if 'tags' in profile:
        #     label = profile['tags']
        # if 'user_id' in profile:
        #     user_id = profile['user_id']
        # if 'ecosystem' in profile:
        #     ecosystem = profile['ecosystem']
        # elif 'ecosystem' in scan_details:
        #     ecosystem = scan_details['ecosystem']
        
        # if 'os_name' in profile:
        #     os_name = profile['os_name']
        # else:
        #     os_name = ''
        # if 'os_version' in profile:
        #     os_version = profile['os_version']
        # else:
        #     os_version = ''
        
        # if 'os_id' in profile:
        #     os_id = profile['os_id']
        # else:
        #     os_id = ''

        # if 'os_version_id' in profile:
        #     os_version_id = profile['os_version_id']
        # else:
        #     os_version_id = ''

        # if 'os_pretty_name' in profile:
        #     os_pretty_name = profile['os_pretty_name']
        # else:
        #     os_pretty_name = ''

        # if 'os_support_url' in profile:
        #     os_support_url = profile['os_support_url']
        # else:
        #     os_support_url = ''

        # if 'os_version_codename' in profile:
        #     os_version_codename = profile['os_version_codename']
        # else:
        #     os_version_codename = ''

        # if 'os_codename' in profile:
        #     os_codename = profile['os_codename']
        # else:
        #     os_codename = ''
        
    

        # if scanner_type == "dependencies":
        #     language = scan_details['language']
        #     ecosystem = language
        # if scanner_type == "dependencies":
        #    language = project_details['language']
        #    ecosystem = language
        #elif scanner_type == "system":
        #    destro = scan_details['destro']
        #    ecosystem = destro

        now = datetime.now()
    
        results = {}
        results['header'] = {}
        # results['header']['Project'] = name
        # results['header']['owner'] = user_id
        # results['header']['company_id'] = company_id
        # results['header']['team_id'] = team_id
        # results['header']['docker'] = docker
        # results['header']['tags'] = label
        # results['header']['scanner_type'] = scanner_type
        results['header']['projectId'] = projectid
        results['header']['scanId'] = scanid
        # results['header']['connection name'] = connname
        # if os_name:
        #     results['header']['os name'] = os_name
        # if os_version:
        #     results['header']['os version'] = os_version
        # if os_id:
        #     results['header']['os_id'] = os_id
        # if os_version_id:
        #     results['header']['os_version_id'] = os_version_id
        # if os_pretty_name:
        #     results['header']['os_pretty_name'] = os_pretty_name
        # if os_support_url:
        #     results['header']['os_support_url'] = os_support_url
        # if os_version_codename:
        #     results['header']['os_version_codename'] = os_version_codename
        # if os_codename:
        #     results['header']['os_codename'] = os_codename

        # project_details = json.dumps(project_details)
        # print("112233",project_details)
        
        # for k, v in eval(project_details).items():
        #     results['header'][k] = v

        # for k, v in scan_details.items():
        #     results['header'][k] = v

        inventory = self.get_inventory(sbomdata)
        results['inventory'] = inventory
        # ecosystem = "rhel"
        vuln_data = self.syncData(ecosystem)

        ecosystem_vulnerability_db = {}
        ecosystem_vulnerability_db['ecosystem'] = ecosystem
        ecosystem_vulnerability_db['db'] = vuln_data['data']

        results['Issues'] = {}

        print("[ INFO ] Scanning started")
        issues_db = self.vuln_parser(ecosystem_vulnerability_db, inventory)
        print("[ INFO ] Scanning completed")

        results['Issues']['data'] = issues_db['issues']
        
        results['header']['Tested With'] = ''
        results['header']['Severity'] = {}
        results['header']['Total Scanned Dependancies'] = len(issues_db['pkg_counts'])
        results['header']['Total Unique Vulnerabilities'] = len(issues_db['vuln_found'])
        results['header']['Total Vulnerable Dependencies'] = len(issues_db['vuln_pkg_counts'])

        for severity in issues_db['severities']:
            results['header']['Severity'][severity] = len(issues_db['severities'][severity])

        return results

if __name__ == "__main__":
    helpText = """
                    Need four arguments : <connectory type> <connector name> <repo name> <branch name>
                    Example  : 
                            niah scan dependancies github conn1 repo1 branch1 (If you need to pull specific branch)
                            niah scan dependancies github conn1 repo1 '' (If you need to pull latest available code)
                """

    parser = argparse.ArgumentParser()
    parser.add_argument('-v', '--version', action='version', version='%(prog)s 1.0')
    parser.add_argument('-k', '--key', type=str, help='Enter API Key')
    parser.add_argument('-i', '--ip', type=str, help='Enter API Server IP')
    parser.add_argument('-s', '--scanid', type=str,  help='Enter scanid')
    parser.add_argument('-p', '--projectid', type=str,  help='Enter Projectname')
    parser.add_argument('-l', '--label', type=str,  help='Enter tags')
    parser.add_argument('-n', '--name', type=str,  help='Enter name')
    parser.add_argument('-t', '--stype', type=str,  help='Enter scanner typer dependencies/system')
    parser.add_argument('-sbom', '--sbom', type=str,  help='Enter sbom file')
    parser.add_argument('-docker', '--docker', type=str,  help='Enter docker yes/no')
    parser.add_argument('-destro', '--destro', type=str,  help='Enter destro name!! example:ubuntu/debian/redhat')
    parser.add_argument('-language', '--language', type=str,  help='Enter sbom language name')

    results = parser.parse_args()


    home_directory = os.path.expanduser( '~' )


    report_save_path = home_directory

    if not results.key:
        print("[ OK ] Enter API Key")
        sys.exit(1)

    if not results.ip:
        print("[ OK ] Enter API Server IP")
        sys.exit(1)

    if not results.sbom:
        print("[ OK ] Enter SBOM Filepath")
        sys.exit(1)

    with open(results.sbom, "r") as f:
        sbomdata = json.load(f)

    res = niah_scanner_sbom()

    if results.projectid and results.scanid:
        if not results.label:
            print("[ OK ] Enter label/tags to scan")
            sys.exit(1)

        res.scan_with_scanid(results.key, results.scanid, sbomdata, results.label, report_save_path, results.ip)

    elif results.projectid and not results.scanid:
        if not results.label:
            print("[ OK ] Enter label/tags to scan")
            sys.exit(1)
        
        scan_details = {}

        if results.stype == "dependencies":
            if results.language:
                language = results.language
                ecosystem = language
                scan_details['language'] = language
                scan_details['ecosystem'] = ecosystem
            else:
                print("[ OK ] Select --language argument")
                sys.exit()
        elif results.stype == "system":
            if results.destro:
                destro = results.destro
                ecosystem = destro
                scan_details['destro'] = destro
                scan_details['ecosystem'] = ecosystem
            else:
                print("[ OK ] Select --destro argument")
                sys.exit()
           
        res.scan_with_projectid(results.key, results.projectid, sbomdata, report_save_path, results.stype, results.label, scan_details, results.ip)

    elif not results.projectid and results.scanid:
        print("[ OK ] Enter --projectid to scan")
        sys.exit(1)
    else:
        if not results.name or not results.label or not results.stype:
            print("[ OK ] Enter --name or --label or --stype option")
            sys.exit()

        scan_details = {}

        if results.stype == "dependencies":
            if results.language:
                language = results.language
                ecosystem = language
                scan_details['language'] = language
                scan_details['ecosystem'] = ecosystem
            else:
                print("[ OK ] Select --language argument")
                sys.exit()
        elif results.stype == "system":
            if results.destro:
                destro = results.destro
                ecosystem = destro
                scan_details['destro'] = destro
                scan_details['ecosystem'] = ecosystem
            else:
                print("[ OK ] Select --destro argument")
                sys.exit()

        res.scan_default(results.key, results.name, results.stype, results.label, scan_details, results.docker, report_save_path, results.ip)



        
        
                