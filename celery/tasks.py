import time
import sys
import re
import json
import os
from celery import Celery
import requests
import configparser
from datetime import datetime, date, timedelta
import glob2
from pathlib import Path
import configparser
import os.path
from passive_api import get_json_feeds 
import shortuuid
import xmltodict
import yaml
from niah_advisor import niah_advisor_scan
from niah import niah_scanner_sbom
from niah_advisor_tags import niah_advisor_scan_tags


datastore = '/opt/sandbox'

settings = configparser.ConfigParser()
settings.read('config.cfg')
username = settings.get('rabbitmq', 'username')
password = settings.get('rabbitmq', 'password')
ipaddr = settings.get('rabbitmq', 'ipaddr')
vhost = settings.get('rabbitmq', 'vhost')


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

def get_vector(jsondata):

    keys = list(jsondata.keys())


    for key in keys:
        if "CVE" in key or "NIAH" in key:
            year = key.split("-")[1]
            # ##print(year)
            file_path = "nvd/cves/%s/%s.json" % (year, key)

            if os.path.exists(file_path):
                with open(file_path, "r") as f:
                    data = json.load(f)

                    
                
                published_date = data['publishedDate']
                modified_date = data['lastModifiedDate']

                jsondata[key]["published_date"] = published_date
                jsondata[key]["modified_date"] = modified_date
                
            
                if 'impact' in data:
                    if 'baseMetricV2' in data['impact']:
                        if 'cvssV2' in data['impact']['baseMetricV2']:
                            if 'accessVector' in data['impact']['baseMetricV2']['cvssV2']:
                                accessVector = data['impact']['baseMetricV2']['cvssV2']['accessVector']
                            elif 'attackVector' in data['impact']['baseMetricV2']['cvssV2']:
                                accessVector = data['impact']['baseMetricV2']['cvssV2']['attackVector']
                            else:
                                accessVector = "UNKNOWN"
                        else:
                            accessVector = "UNKNOWN"
                    elif 'baseMetricV3' in data['impact']:
                        if 'cvssV3' in data['impact']['baseMetricV3']:
                            if 'accessVector' in data['impact']['baseMetricV3']['cvssV3']:
                                accessVector = data['impact']['baseMetricV3']['cvssV3']['accessVector']
                            elif 'attackVector' in data['impact']['baseMetricV3']['cvssV3']:
                                accessVector = data['impact']['baseMetricV3']['cvssV3']['attackVector']
                            else:
                                accessVector = "UNKNOWN"
                        else:
                            accessVector = "UNKNOWN"
                    else:
                        accessVector = "UNKNOWN"
                else:
                    accessVector = "UNKNOWN"
                
                
                jsondata[key]["accessVector"] = accessVector


                if 'impact' in data:
                    if 'baseMetricV3' in data['impact']:
                        if 'cvssV3' in data['impact']['baseMetricV3']:
                            if 'baseSeverity' in data['impact']['baseMetricV3']['cvssV3']:
                                severity = data['impact']['baseMetricV3']['cvssV3']['baseSeverity']
                                if severity == "MEDIUM":
                                    severity = "MODERATE"
                            else:
                                severity = "UNKNOWN"
                        else:
                            severity = "UNKNOWN"
                    elif 'baseMetricV2' in data['impact']:
                        if 'cvssV2' in data['impact']['baseMetricV2']:
                            if 'severity' in data['impact']['baseMetricV2']['cvssV2']:
                                severity = data['impact']['baseMetricV2']['cvssV2']['severity']
                                if severity == "MEDIUM":
                                    severity = "MODERATE"
                            else:
                                severity = "UNKNOWN"
                        else:
                            severity = "UNKNOWN"
                    else:
                        severity = "UNKNOWN"
                else:
                    severity = "UNKNOWN"

                jsondata[key]["severity"] = severity
            else:
                print("file not found")
        else:
            print("file not found")

    return jsondata



def get_language(repo):
    if repo == "pypi":
        language  = "python"
    if repo == "npm":
        language  = "javascript"
    if repo == "maven":
        language  = "java"
    if repo == "packagist":
        language  = "php"
    if repo == "rubygems":
        language  = "ruby"
    if repo == "nuget":
        language  = "c#"
    if repo == "pub":
        language  = "dart"
    if repo == "hex":
        language  = "elixir"
    if repo == "crates.io":
        language  = "rust"
    if repo == "go":
        language  = "go"
    if repo == "oss-fuzz":
        language  = "c"
    if repo == "nvd":
        language  = "unknown"
    
    return language

def get_dep_data(repo):
    try:
        if repo == "maven":
            dep_file = 'java_dep.json'
            rev_file = 'java_rev.json' 
        if repo == "nuget":
            dep_file = 'c#_dep.json'
            rev_file = 'c#_rev.json'
        if repo == "pub":
            dep_file = 'dart_dep.json'
            rev_file = 'dart_rev.json'
        if repo == "debian":
            dep_file = 'debian_dep.json'
            rev_file = 'debian_rev.json'
        if repo == "hex":
            dep_file = 'elixir_dep.json'
            rev_file = 'elixir_rev.json'
        if repo == "npm":
            dep_file = 'javascript_dep.json'
            rev_file = 'javascript_rev.json'
        if repo == "packagist":
            dep_file = 'php_dep.json'
            rev_file = 'php_rev.json'
        if repo == "pypi":
            dep_file = 'python_dep.json'
            rev_file = 'python_rev.json'
        if repo == "rubygems":
            dep_file = 'ruby_dep.json'
            rev_file = 'ruby_rev.json'
        if repo == "ubuntu":
            dep_file = 'ubuntu_dep.json'
            rev_file = 'ubuntu_rev.json'
        if repo == "crates.io":
            dep_file = 'crate_dep.json'
            rev_file = 'crate_rev.json'

        if dep_file != None and rev_file != None:
            with open("/var/DB/feeds/deps/%s" % dep_file, 'r') as f:
                dep_data = json.load(f)
                # print(dep_data)
            with open("/var/DB/feeds/deps/%s" % rev_file, 'r') as f:
                rev_data = json.load(f)
        else:
            pass

        return dep_data, rev_data
    except:
        return None

def get_file_dataset(file, repo):

    file_dataset = {}
    
    with open(file, "r") as f:
        print("get file dataset running for %s" % file)
        data = json.load(f)   

    res = {}
    if repo == 'cpp':            
        res['id'] = data['cve']['CVE_data_meta']['ID']
        res['CVEs'] = []
        res['ecosystem'] = 'cpp'
        res['language'] = 'cpp'
        res['vendor'] = ''
        res['product'] = ''
        res['dependency'] = []

        if 'impact' in data:
            if 'baseMetricV3' in data['impact']:
                if 'cvssV3' in data['impact']['baseMetricV3']:
                    if 'baseSeverity' in data['impact']['baseMetricV3']['cvssV3']:
                        severity = data['impact']['baseMetricV3']['cvssV3']['baseSeverity']
                        if severity == "MEDIUM":
                            severity = "MODERATE"
                        ##print(severity)
                    else:
                        severity = "UNKNOWN"
                else:
                    severity = "UNKNOWN"
            else:
                severity = "UNKNOWN"
        else:
            severity = "UNKNOWN"



        res['severity'] = severity

        res['reverse_dep'] = []
        res['packagename'] = ''

    elif repo == 'noncve':
        print(data)

        res['id'] = data['niah_id']
        res['CVEs'] = []
        res['ecosystem'] = file.split("/")[0]
        res['language'] = file.split("/")[0]
        res['vendor'] = data['vendor']
        res['product'] = data['product']
        res['severity'] = "UNKNOWN"
        res['dependency'] = ''
        res['published_date'] = data['commit_date']
        res['reverse_dep'] = ''
        res['packagename'] = ''


    elif repo == "oracle-linux":
        if 'cve_id' in data:
            res['id'] = data['cve_id'] 
        else:
            res['id'] = ''
        res['ecosystem'] = 'oracle-linux'
        res['language'] = ''
        res['vendor'] = ''
        res['product'] = ''
        res['severity'] = "UNKNOWN"
        res['packagename'] = ''



    elif repo == "suse-linux":
        if 'Title' in data:
            res['id'] = data['Title'] 
        else:
            res['id'] = ''

        res['ecosystem'] = 'suse-linux'
        res['language'] = ''
        res['vendor'] = ''
        res['product'] = ''
        res['packagename'] = ''

        severity = data['Threat']
        if severity is not None:
            severity = severity.upper()
        if severity == 'IMPORTANT':
            severity = 'HIGH'
        if severity == '':
            severity = "UNKNOWN"

        res['severity'] = severity

    elif repo == "rhel":
        if 'CVE' in data:
            res['id'] = data['CVE'] 
        else:
            res['id'] = ''

        res['ecosystem'] = 'rhel'
        res['language'] = ''
        res['vendor'] = ''
        res['product'] = ''
        res['packagename'] = ''

        severity = data['severity']
        if severity is not None:
            severity = severity.upper()
        if severity == 'IMPORTANT':
            severity = 'HIGH'

        if severity == '':
            severity = "UNKNOWN"

        res['severity'] = severity


    elif repo == "ubuntu":
        if 'cve_id' in data:
            res['id'] = data['cve_id'] 
        elif 'id' in data:
            res['id'] =  data['id']
        else:
            res['id'] = ''


        res['ecosystem'] = 'ubuntu'
        res['language'] = ''
        res['vendor'] = ''
        res['product'] = ''
        res['packagename'] = ''

        res['severity'] = "UNKNOWN"

        accessVector = "UNKNOWN"
                
        res['accessVector'] = accessVector

    elif repo == 'debian':
        ##print(data)

        if 'aliases' in data:
            if len(data['aliases']) > 0:
                res['id'] = data['aliases'][0] 
            elif 'id' in data:
                res['id'] = data['id']
            else:
                res['id'] = ''
        
        if 'related' in data:
            if len(data['related']) > 0:
                res['id'] = data['related'][0] 
            elif 'id' in data:
                res['id'] = data['id']
            else:
                res['id'] = ''
        

        if 'affected' in data:
            if len(data['affected']) > 0:
                if 'package' in data['affected'][0]:
                    if 'ecosystem' in data['affected'][0]['package']:
                        installer = data['affected'][0]['package']['ecosystem']
        # ecosystem = installer.lower()

        res['language'] = ''
        res['ecosystem'] = 'debian'
        res['accessVector'] = 'UNKNOWN'
        
                
        if 'affected' in data:
            if len(data['affected']) > 0:
                if 'package' in data['affected'][0]:
                    if 'ecosystem' in data['affected'][0]['package']:
                        packagename = data['affected'][0]['package']['name']
                    else:
                        packagename = ''
                else:
                    packagename = ''
            else:
                packagename = ''
        else:
            packagename = ''


        res['packagename'] = packagename


    elif repo == 'nvd':
        # ##print(data)

        res['id'] = data['cve']['CVE_data_meta']['ID']
        
        res['published_date'] = data['publishedDate']
        res['modified_date'] = data['lastModifiedDate']


        if 'impact' in data:
            if 'baseMetricV3' in data['impact']:
                if 'cvssV3' in data['impact']['baseMetricV3']:
                    if 'accessVector' in data['impact']['baseMetricV3']['cvssV3']:
                        res['accessVector'] = data['impact']['baseMetricV3']['cvssV3']['accessVector']
                    else: 
                        res['accessVector'] = 'UNKNOWN'
                else: 
                    res['accessVector'] = 'UNKNOWN'
            else: 
                res['accessVector'] = 'UNKNOWN'
        else: 
            res['accessVector'] = 'UNKNOWN'


        res['language'] = ''
        res['ecosystem'] = 'nvd'
        # res['accessVector'] = 'UNKNOWN'
        

    else:
        if 'aliases' in data:
            if len(data['aliases']) > 0:
                res['id'] = data['aliases'][0] 
            else:
                res['id'] = ''
            ##print(res['id'])

        if 'affected' in data:
            if len(data['affected']) > 0:
                if 'package' in data['affected'][0]:
                    if 'ecosystem' in data['affected'][0]['package']:
                        installer = data['affected'][0]['package']['ecosystem']

        res['language'] = get_language(repo)
        res['ecosystem'] = get_language(repo)
        res['published_date'] = data['published']
        res['modified_date'] = data['modified']
        
                
        if 'affected' in data:
            if len(data['affected']) > 0:
                if 'package' in data['affected'][0]:
                    if 'ecosystem' in data['affected'][0]['package']:
                        packagename = data['affected'][0]['package']['name']
                    else:
                        packagename = ''
                else:
                    packagename = ''
            else:
                packagename = ''
        else:
            packagename = ''

        # if 'database_specific' in data:
        #     if 'severity' in data['database_specific']:
        #         severity = data['database_specific']['severity']
        #         ##print(severity)
        #     else:
        #         severity = 'UNKNOWN'
        # else:
        #     severity = 'UNKNOWN'

        # res['severity'] = severity

        res['packagename'] = packagename

    return res


# print("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",file_dataset,"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")


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

if not os.path.isdir('/var/run/celery'):
    status, output = getstatusoutput("sudo mkdir /var/run/celery/")
    status, output = getstatusoutput("sudo chmod 777 /var/run/celery/ -R")

if not os.path.isdir('/tmp/users'):
    status, output = getstatusoutput("mkdir /tmp/users")
    status, output = getstatusoutput("chmod 777 /tmp/users -R")

app = Celery('tasks', backend='amqp', broker='amqp://%s:%s@%s/%s' % (username, password, ipaddr, vhost))

app.conf.update(
        CELERY_RESULT_BACKEND = "amqp://",
        CELERY_RESULT_SERIALIZER='json',
    CELERY_ACCEPT_CONTENT = ['json','application/text'],
        )


@app.task
def get_cves_feeds(user_id, cves, filename):
    res = get_json_feeds()

    results = res.get_cves(cves)
    path = '../static/report/%s/passive/' % user_id

    # filename = datetime.today().strftime("%Y-%m-%d_%H-%M") + '.json'
    filepath  = path + filename


    if not os.path.isdir(os.path.dirname(path)):
        os.makedirs(os.path.dirname(path))

    with open(filepath, "w") as outfile:
        json.dump(results, outfile, indent=2)

    return results

@app.task
def get_year_feeds(user_id, years, filename):
    res = get_json_feeds()

    results = res.get_year(years)

    path = '../static/report/%s/passive/' % user_id

    # filename = datetime.today().strftime("%Y-%m-%d_%H-%M") + '.json'
    filepath  = path + filename

    if not os.path.isdir(os.path.dirname(path)):
        os.makedirs(os.path.dirname(path))

    with open(filepath, "w") as outfile:
        json.dump(results, outfile, indent=2)

    return results

@app.task
def get_packages_feeds(user_id, packages, echosystem, filename):
    print("u",user_id)
    print("p",packages)
    print("e",echosystem)
    print("f",filename)

    res = get_json_feeds()
    results = res.get_packages(packages, echosystem)

    path = '../static/report/%s/passive/' % user_id

    filepath  = path + filename

    if not os.path.isdir(os.path.dirname(path)):
        os.makedirs(os.path.dirname(path))

    with open(filepath, "w") as outfile:
        json.dump(results, outfile, indent=2)

    return results

@app.task
def get_echosystem_feeds(user_id, echosystem, filename):
    res = get_json_feeds()
    results = res.get_echosystem_vuln(echosystem)

    path = '../static/report/%s/passive/' % user_id

    filepath  = path + filename
    print("11111111 %s" %filepath)

    if not os.path.isdir(os.path.dirname(path)):
        os.makedirs(os.path.dirname(path))

    with open(filepath, "w") as outfile:
        json.dump(results, outfile, indent=2)

    return results


@app.task
def sbom_file_default(filename, filepath, sbom_dir, unique_file_name):

    
    print(filename)
    print(filepath)
    
    res = {}
    os.chdir("/home/niah")

    try:
        cmd = "sudo chmod 777 -R /home/ftpuser/uploads"
        print(cmd)
        status, output = getstatusoutput(cmd)

        cmd = "sudo /usr/local/bin/syft packages file:%s/%s -o cyclonedx-json=%s/%s.json" % (filepath, filename, sbom_dir, unique_file_name)
        print(cmd)
        status, output = getstatusoutput(cmd)

        cmd = "sudo /usr/local/bin/syft packages file:%s/%s -o cyclonedx-xml=%s/%s.xml" % (filepath, filename, sbom_dir, unique_file_name)
        print(cmd)
        status, output = getstatusoutput(cmd)
    
        res['res_status'] = "Success"
        res['detail'] = "SBOM Created Successfully..!!"

    except:
        res['res_status'] = "Failed"
        res['detail'] = "SBOM creation failed..! Please upload file with valid data.."

    return res    
   
    
  


@app.task
def sbom_docker_file_default(filename, filepath, sbom_dir, unique_file_name):
    os.chdir("/home/niah")
    res = {}
    outputfile = shortuuid.uuid()
    cmd = "mkdir /tmp/%s" % outputfile
    print(cmd)
    status, output = getstatusoutput(cmd)
    print(output)

    # print("2222", filepath)
    
    cmd = "sudo chmod 777 -R /home/ftpuser/uploads"
    print(cmd)
    status, output = getstatusoutput(cmd)
    print(output) 

    cmd = "sudo chmod 777 -R /tmp/%s" % outputfile
    print(cmd)
    status, output = getstatusoutput(cmd)
    print(output)

    cmd = "unzip %s/%s -d /tmp/%s" % (filepath, filename, outputfile)
    print(cmd)
    status, output = getstatusoutput(cmd)
    print(output)

    docker_dir = filename.split("_00_")[-1]
    print(docker_dir)

    cmd = "docker build --tag %s/%s:1 /tmp/%s/%s" % (outputfile.lower(), outputfile.lower(), outputfile, docker_dir.replace(".zip", ""))
    print(cmd)
    status, output = getstatusoutput(cmd)
    print(output)

    cmd = "docker images | grep %s/%s" % (outputfile.lower(), outputfile.lower())
    print(cmd)
    status, output = getstatusoutput(cmd)
    print(output)

    if "%s/%s" % (outputfile.lower(), outputfile.lower()) in output:

        cmd = "/usr/local/bin/syft packages docker:%s/%s:1 -o cyclonedx-json=%s/%s.json" % (outputfile.lower(), outputfile.lower(), sbom_dir, unique_file_name)
        print(cmd)
        status, output = getstatusoutput(cmd)
        print(output)

        cmd = "/usr/local/bin/syft packages docker:%s/%s:1 -o cyclonedx-xml=%s/%s.xml" % (outputfile.lower(), outputfile.lower(), sbom_dir, unique_file_name)
        print(cmd)
        status, output = getstatusoutput(cmd)
        print(output)


        cmd = "docker rmi %s/%s:1" % (outputfile.lower(), outputfile.lower())
        print(cmd)
        status, output = getstatusoutput(cmd)

        res['res_status'] = "Success"
        res['detail'] = "SBOM Created Successfully..!!"
    
    else:
        res['res_status'] = "Failed"
        res['detail'] = "Image not build, please upload Valid Zip file."

    return res

    

    # cmd = "rm -rf /tmp/%s" % outputfile
    # print(cmd)
    # status, output = getstatusoutput(cmd)    
    
        
@app.task
def sbom_docker_repo_default(docker_repo_name, sbom_dir, unique_file_name):
    os.chdir("/home/niah")
    res = {}
    print("sb", unique_file_name)


    cmd = "docker pull %s" % docker_repo_name
    print(cmd)
    status, output = getstatusoutput(cmd)
    print(output)
    if "Pull complete" in output:

        os.chdir("..")

        cmd = "syft packages %s -o cyclonedx-xml=%s/%s.xml" % (docker_repo_name, sbom_dir, unique_file_name)
        print(cmd)
        status, output = getstatusoutput(cmd)

        cmd = "syft packages %s -o cyclonedx-json=%s/%s.json" % (docker_repo_name, sbom_dir, unique_file_name)
        print(cmd)
        status, output = getstatusoutput(cmd)

        cmd = "docker rmi %s:latest" % docker_repo_name
        print(cmd)
        status, output = getstatusoutput(cmd)

        res['res_status'] = "Success"
        res['detail'] = "SBOM Created Successfully..!!"
    
    else:
        res['res_status'] = "Failed"
        res['detail'] = "Repository does not exist, please Enter valid repository name"

    return res


        
@app.task
def sbom_git_repo_default(git_repo_url, sbom_dir, unique_file_name):
    res = {}
    os.chdir("/home/niah")
    outputfile = shortuuid.uuid()

    cmd = "mkdir /tmp/%s" % outputfile
    print(cmd)
    status, output = getstatusoutput(cmd)

    os.chdir("/tmp/%s" % outputfile)

    print(git_repo_url)
    print(os.getcwd())

    cmd = "git clone %s" % git_repo_url
    print(cmd)
    status, output = getstatusoutput(cmd)
    
    git_repo_name = os.path.basename(git_repo_url).replace(".git","")
    
    repo_location = "/tmp/%s/%s" % (outputfile, git_repo_name)

    if "Username for" not in output:
        
        if os.path.exists(repo_location):

            cmd = "syft packages %s -o cyclonedx-xml=%s/%s.xml" % (repo_location, sbom_dir, unique_file_name)
            print(cmd)
            status, output = getstatusoutput(cmd)

            cmd = "syft packages %s -o cyclonedx-json=%s/%s.json" % (repo_location, sbom_dir, unique_file_name)
            print(cmd)
            status, output = getstatusoutput(cmd)

            # cmd = "rm -rf /tmp/%s" % outputfile
            # print(cmd)
            # status, output = getstatusoutput(cmd)
            res['res_status'] = "Success"
            res['detail'] = "SBOM Created Successfully..!!"
        else:
            res['res_status'] = "Failed"
            res['detail'] = "Repository not cloned, please Enter valid repository url in format asked.."
    else:
        res['res_status'] = "Failed"
        res['detail'] = "Repository not cloned, please Enter valid repository url in format asked.."

    return res
    



@app.task
def sbom_dpkg_file_default(distro, filepath, filename, sbom_dir, unique_file_name):
    outputfile = shortuuid.uuid()
    os.chdir("/home/niah")
    res = {}

    cmd = "sudo chmod 777 -R /home/ftpuser/uploads"
    status, output = getstatusoutput(cmd)

    try:
        cmd = "distro2sbom --distro %s --name niah-sbom-destro --release niah1.1 --input-file %s/%s --sbom cyclonedx --system --format yaml --output-file %s/%s.yaml" % (distro, filepath, filename, sbom_dir, unique_file_name)
        print(cmd)
        status, output = getstatusoutput(cmd)


        cmd = "distro2sbom --distro %s --name niah-sbom-destro --release niah1.1 --input-file %s/%s --sbom cyclonedx --system --format json --output-file %s/%s.json" % (distro, filepath, filename, sbom_dir, unique_file_name)
        print(cmd)
        status, output = getstatusoutput(cmd)


        with open('%s/%s.yaml' % (sbom_dir, unique_file_name), "r") as yamlfile:
            yaml_data = yaml.safe_load(yamlfile)
            
        wrapped_data = {'root': yaml_data}
            
        json_data = json.dumps(wrapped_data, indent=2)
        parsed_data = json.loads(json_data)

        xml_data = xmltodict.unparse(parsed_data, pretty=True)
        print(xml_data)

        with open('%s/%s.xml' % (sbom_dir, unique_file_name), 'w') as file:
            file.write(xml_data)

        cmd = "rm -rf %s/%s.yaml" % (sbom_dir, unique_file_name)
        print(cmd)
        status, output = getstatusoutput(cmd)

        res['res_status'] = "Success"
        res['detail'] = "SBOM Created Successfully..!!"
    except:
        res['res_status'] = "Failed"
        res['detail'] = "SBOM creation failed..! Please upload file with valid data.."

    return res

@app.task
def get_committed_files_in_period(start_date, end_date):
    # file_list = []
    period_dataset = {}
    os.chdir('/home/niah/work2')

    repos = ['maven','pub','pypi','rubygems','hex','npm','nuget','packagist', 'nvd','go','noncve','cpp','crates.io','oss-fuzz','ubuntu','oracle-linux','suse-linux','rhel','debian']
    

    for repo in repos:
        file_list = []

        os.chdir(repo)

        ##print(os.getcwd())

        cmd = 'git log --name-only --pretty=format: --since="%s" --until="%s" | sort -u' % (start_date, end_date)
        status, output = getstatusoutput(cmd)
        ##print(cmd)

        file_list.extend(output.split("\n"))
        if '' in file_list:
            file_list.remove('')
        for filename in file_list:
            if '.json' not in filename:
                file_list.remove(filename)

        ##print("files", file_list)
        # try:
        for file in file_list:
            ##print(file, repo)
            if "CVE" in file or "PYSEC" in file or "GHSA" in file or "USN" in file or "DLA" in file or "DSA" in file or "GO" in file or "NIAH" in file:
                try:
                    res = get_file_dataset(file, repo)


                    print(res)

                    if os.path.exists(file):
                        try:
                            if res['id'] != '' and ("CVE-" in res['id'] or "NIAH" in res['id']):
                                period_dataset[res['id']] = res
                                    
                            else:
                                ##print('File Deleted or Not found..!')
                                pass
                        except:
                            pass
                except:
                    print('File Deleted or Not found..!')
            else:
                pass
                        
                # except:
                #     ##print('Invalid file..!!')

        os.chdir("..")


    jsondata = get_vector(period_dataset)

    print("22222",period_dataset)

    output = {}
    output['chart'] = {}
    output['chart']['severity'] = {}
    output['chart']['platforms'] = {}
    output['chart']['ecosystems'] = {}
    output['chart']['accessVector'] = {}

    # SEVERITY
    severity_counts = {'HIGH': 0, 'MODERATE': 0, 'LOW': 0, 'CRITICAL': 0, 'UNKNOWN': 0}

    for item in jsondata.values():
        try:
            severity = item['severity']
            if severity in severity_counts:
                severity_counts[severity] += 1
        except:
            pass

    output['chart']['severity'] = severity_counts


    # ACCESS VECTOR
    # for item in jsondata.values():
    #     ##print(item)
    #     accessVector = item['accessVector']
    #     accessVector = accessVector.upper()
    
    # output['chart']['accessVector'][accessVector] = output['chart']['accessVector'].get(accessVector, 0) + 1



    vector_count = {'NETWORK': 0, 'LOCAL': 0,'PHYSICAL':0, 'UNKNOWN': 0, 'ADJACENT_NETWORK':0}
    avs = []
    for item in jsondata.values():
        try:
            accessVector = item['accessVector']
            accessVector = accessVector.upper()
            if accessVector not in avs:
                avs.append(accessVector)

            if accessVector not in avs:
                avs.append(accessVector)
            if accessVector in vector_count:
                vector_count[accessVector] += 1
        except:
            pass

    output['chart']['accessVector'] = vector_count


    # VULNERABILITY
    platform_list = ["ubuntu", "debian", "oracle-linux", "suse-linux", "rhel"]
    # platform_list = {'ubuntu': 0, 'debian': 0, 'oracle-linux': 0, 'suse-linux': 0, 'rhel': 0}
    # ecosystems_list = {'python': 0, 'javascript': 0, 'java': 0, 'php': 0, 'ruby': 0, 'c#': 0, 'dart': 0, 'elixir': 0, 'rust': 0, 'go': 0, 'c': 0}
    
    for item in jsondata.values():

        if "NIAH" in item['id']:
            eco = item['language']
        else:
            eco = item["ecosystem"]

        ##print(eco)

        if eco in platform_list:
            output['chart']['platforms'][eco] = output['chart']['platforms'].get(eco, 0) + 1
        else:
            output['chart']['ecosystems'][eco] = output['chart']['ecosystems'].get(eco, 0) + 1

    
    langs = ['python', 'javascript', 'java', 'php', 'ruby', 'c#', 'dart', 'elixir', 'rust', 'go', 'c']
    plats = ['ubuntu', 'debian', 'oracle-linux', 'suse-linux', 'rhel']


    ##print(output)

    sorted_data = {}
    sorted_data['platforms'] = {}
    sorted_data['ecosystems'] = {}
    sorted_data['nvd'] = {}
    sorted_data['noncve'] = {}


    for item in jsondata.values():
        lang = item["ecosystem"]
        id = item['id']

        if lang in langs:
            sorted_data['ecosystems'][id] = item
        elif lang in plats:
            sorted_data['platforms'][id] = item
        else:
            sorted_data['nvd'][id] = item
    
    for item in period_dataset.values():
        if "NIAH" in item['id']:
            sorted_data['noncve'][id] = item
        

    output['data'] = sorted_data

    print(avs)

    return output



@app.task
def advisor_ecopack(ecosystem, package):

    res = niah_advisor_scan()
    
    pack_details = res.get_pack_details(ecosystem, package)

    print(pack_details)

    return pack_details


@app.task
def advisor_ecopack_tag(ecosystem, package, tags, github_url):

    sbom_name = "/mnt/niahdb/niah-advisor/niah_pack/%s/%s/sbom/%s_%s_sbom.json" % (ecosystem, package, package, tags)
    report_name = "/mnt/niahdb/niah-advisor/niah_pack/%s/%s/vuln/%s_%s_report.json" % (ecosystem, package, package, tags)

    tag_report_details = {}
    tag_report_details['vuln_report'] = {}


    if ecosystem == "pypi":
        ecosystem = "python"
    if ecosystem == "ruby":
        ecosystem = "ruby"
    if ecosystem == "npm":
        ecosystem = "javascript"
    if ecosystem == "hex":
        ecosystem = "elixir"
    if ecosystem == "nuget":
        ecosystem = "c"
    if ecosystem == "pub":
        ecosystem = "dart"
    if ecosystem == "crates":
        ecosystem = "rust"
    if ecosystem == "composer":
        ecosystem = "php"

    # try:

    if str(github_url).endswith(".git"):
        github_url = str(github_url).replace(".git", "")

    repo = str(github_url).split("/")[-1]
    print(repo)


    os.chdir("repos")
    print(os.getcwd())

    cmd = "GIT_ASKPASS=echo git clone -b %s %s.git" % (tags, github_url)
    print(cmd)
    status, output = getstatusoutput(cmd)
    
    cmd = "sudo /usr/local/bin/syft packages dir:%s -o cyclonedx-json=%s" % (repo, sbom_name)
    status, output = getstatusoutput(cmd)
    print(cmd)

    with open(sbom_name, "r") as f:
        sbomdata = json.load(f)
        print("sbom data loaded")

    res = niah_scanner_sbom()
    report_results = res.scan_bom(sbomdata, ecosystem)

    print("XXXXXXXXXXXXXXXXXXXXX\n\n\n", report_results)
    print("Report generated...")

    with open(report_name, "w") as outfile:
        json.dump(report_results, outfile, indent=2)

    tag_report_details['vuln_report'] = report_results


    # cmd = "sudo rm -rf %s" % repo
    # print(cmd)
    # status, output = getstatusoutput(cmd)

    os.chdir("..")

    # except:
    #     pass

    return tag_report_details


