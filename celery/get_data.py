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

# if not os.path.exists("/mnt/niahdb/niah-advisor/niah_pack"):
#     os.mkdir("/mnt/niahdb/niah-advisor/niah_pack")

# if not os.path.exists("/home/niah/extra/repos"):
#     os.mkdir("/home/niah/extra/repos")
class niah_advisor_scan():

    def get_commits_by_day(self, owner, repo):
        commits_by_day = {}
        today = datetime.date.today()
        last_week = today - datetime.timedelta(days=7)

        while today > last_week:
            date_str = today.strftime("%Y-%m-%d")
            api_url = f"https://api.github.com/repos/{owner}/{repo}/commits?since={date_str}T00:00:00Z&until={date_str}T23:59:59Z"
            response = requests.get(api_url)
            
            if response.status_code == 200:
                commits = response.json()
                commits_by_day[date_str] = len(commits)
            else:
                commits_by_day[date_str] = 0
            
            today -= datetime.timedelta(days=1)

        return commits_by_day


    def get_github_repo_info(self, github_url):
        parts = github_url.strip("/").split("/")
        print("parts", parts)
        owner = parts[-2]
        repo = parts[-1]

        # api_url = f"https://api.github.com/repos/{owner}/{repo}"
        api_url = "https://api.github.com/repos/pytorch/pytorch"
        print("api_url", api_url)

        response = requests.get(api_url)
        print("status", response.status_code)

        if response.status_code == 200:
            repo_data = response.json()

            # print(repo_data)

            stars = repo_data["stargazers_count"]
            print("starts", stars)

            commits = repo_data["commits_url"].replace("{/sha}", "?per_page=100")
            commits = requests.get(commits)
            commits_list = commits.json()

            issues = repo_data["open_issues"]

            prs = repo_data["pulls_url"].replace("{/number}", "?per_page=100")
            responce = requests.get(prs)
            pull_requests = responce.json()


            last_commit = repo_data["pushed_at"]

            forks = repo_data["forks_count"]

            contribs = repo_data["contributors_url"]
            contribs = requests.get(contribs)
            contributors = contribs.json()


            commits_by_day = self.get_commits_by_day(owner, repo)

            github_info = {
                "Stars": stars,
                "Commits": len(commits_list),
                "Issues": issues,
                "PullRequests": len(pull_requests),
                "LastCommit": last_commit,
                "Forks": forks,
                "Contributors": len(contributors),
                "CommitsByDay": commits_by_day

            }
            print("------------------------------\n\n", github_info, "\n\n------------------------------")

            return github_info
        else:
            return None

    def scan_pypi(self, ecosystem , package):
        url = f"https://pypi.org/pypi/{package}/json"

        print(url)
        pack_datails = {}
        # try:
        response = urllib.request.urlopen(url)
        pack_data = json.load(response)
        pack_data['info']['all_tags'] = list(pack_data["releases"].keys())


        file_name = "/mnt/niahdb/niah-advisor/niah_pack/%s/%s/%s.json" % (ecosystem, package, package)
        sbom_name = "/mnt/niahdb/niah-advisor/niah_pack/%s/%s/sbom/%s_latest_sbom.json" % (ecosystem, package, package)
        # print(pack_data)

        with open(file_name, "w") as outfile:
            json.dump(pack_data, outfile, indent=2)
        
        pack_datails = {}
        pack_datails['pack_info'] = pack_data
        pack_datails['repo_info'] = {}
        pack_datails['vuln_report'] = {}

        if "info" in pack_data:
            pack_info = pack_data['info']
            if 'project_urls' in pack_info:
                print(pack_info['project_urls'])

                if 'Code' in pack_info['project_urls']:
                    github_url = pack_info['project_urls']['Code']
                    # pack_datails['repo_info'] = self.get_github_repo_info(github_url)
                    print("Code", github_url)

                elif 'Source' in pack_info['project_urls']:
                    github_url = pack_info['project_urls']['Source']
                    # pack_datails['repo_info'] = self.get_github_repo_info(github_url)
                    print("Source", github_url)

                elif 'Source Code' in pack_info['project_urls']:
                    github_url = pack_info['project_urls']['Source Code']
                    print("Source Code", github_url)
                    # pack_datails['repo_info'] = self.get_github_repo_info(github_url)

                elif 'Repository' in pack_info['project_urls']:
                    github_url = pack_info['project_urls']['Repository']
                    print("Repository", github_url)


                pack_datails['repo_info'] = self.get_github_repo_info(github_url)

                repo = str(github_url).split("/")[-1]
                try:

                    os.chdir("repos")

                    cmd = "GIT_ASKPASS=echo git clone %s.git" % github_url
                    print(cmd)
                    status, output = getstatusoutput(cmd)
                    
                    cmd = "sudo /usr/local/bin/syft packages dir:%s -o cyclonedx-json=%s" % (repo, sbom_name)
                    print(cmd)
                    status, output = getstatusoutput(cmd)

                    cmd = "sudo rm -rf %s" % repo
                    print(cmd)
                    status, output = getstatusoutput(cmd)

                    os.chdir("..")

                except:
                    pass
                else:
                    print("Code not available")
            else:
                print("project_urls not available")
        else:
            print("info not available")
        # except:
        #     pass
            # res = {}
            # res['message'] = "Package not found..!"
        print(pack_datails)
        return pack_datails



    def scan_ruby(self, ecosystem , package):
        pack_url = "https://rubygems.org/gems/%s" % package
    
        print("URL - %s" % pack_url)
        r = requests.get(pack_url)
        htmlContent = r.content
        soup = BeautifulSoup(htmlContent, "html.parser")
        
        data = {}
        package = []
        pname = soup.find('div', class_='l-wrap--b').find('h1').text.strip().replace(" ","")
        p = pname.replace('\n\n', ',')
        package = p.split(",")
        
        p_name = package[0]
        latest_version = package[1]

        p_dis = ''
        if soup.find('div', class_ = "gem__desc"):
            if soup.find('div', class_ = "gem__desc").find('p'):
                p_dis = soup.find('div', class_ = "gem__desc").find('p').text.strip()

        version_url = pack_url + '/versions'
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


        d_dependencies = []
        try:
            d_dep = soup.find('div', id='development_dependencies').find('div',class_='t-list__items')
            for a in d_dep.findAll('li'):
                d_dep1 = a.find('a').text.strip()
                d_dependencies.append(d_dep1)
        except:
            d_dependencies = []

        downloadall = soup.findAll('div', class_="gem__aside l-col--r--pad")[0].findAll('span', class_='gem__downloads')[0]
        downall = downloadall.text.strip()

        downloadthis = soup.findAll('div', class_="gem__aside l-col--r--pad")[0].findAll('span', class_='gem__downloads')[1]
        downthis = downloadthis.text.strip()

        downloads = ({"Total Downloads": downall, "For this version": downthis})
        
        homeurl = ''
        try:
            homeurl = soup.find('div',class_="gem__aside l-col--r--pad").find('div', class_='t-list__items').find('a', class_='gem__link t-list__item', id='home').get('href')
        except:
            homeurl = ''

        downloadurl = ''

        if soup.find('div',class_="gem__aside l-col--r--pad"):
            download_details = soup.find('div',class_="gem__aside l-col--r--pad")
            if download_details.find('div', class_='t-list__items'):
                download_atags = download_details.find('div', class_='t-list__items')
                if download_atags.find('a', class_='gem__link t-list__item', id='download'):
                    downloadurl = download_atags.find('a', class_='gem__link t-list__item', id='download').get('href')

        data['packagename'] = p_name
        data['description'] = p_dis
        data['latest_version'] = latest_version
        data['versions'] = version_list
        data['license'] = license
        data['Runtime_Dependencies'] = r_dependencies
        data['Developer_Dependencies'] = d_dependencies
        data['HomeURL'] = homeurl
        data['DownloadURL'] = downloadurl
        data['downloads'] = downloads

        pack_datails = {}
        pack_datails['pack_info'] = data
        pack_datails['repo_info'] = self.get_github_repo_info(homeurl)
        pack_datails['vuln_report'] = {}

        with open("/mnt/niahdb/niah-advisor/niah_pack/%s/%s/%s.json" % (ecosystem, p_name, p_name), "w") as outfile:
            json.dump(data ,outfile, indent=2)

        sbom_name = "/mnt/niahdb/niah-advisor/niah_pack/%s/%s/sbom/%s_latest_sbom.json" % (ecosystem, p_name, p_name)
        repo = str(homeurl).split("/")[-1]
        try:

            os.chdir("repos")

            cmd = "GIT_ASKPASS=echo git clone %s.git" % homeurl
            print(cmd)
            status, output = getstatusoutput(cmd)
            
            cmd = "sudo /usr/local/bin/syft packages dir:%s -o cyclonedx-json=%s" % (repo, sbom_name)
            print(cmd)
            status, output = getstatusoutput(cmd)

            cmd = "sudo rm -rf %s" % repo
            print(cmd)
            status, output = getstatusoutput(cmd)

            os.chdir("..")

        except:
            pass
        
        return pack_datails


    def scan_npm(self, ecosystem, package):
        url = "https://registry.npmjs.org/%s" % package

        try:
            response = urllib.request.urlopen(url)
            data = json.load(response)

            if 'name' in data:
                p_name = data["name"]
            else:
                name = ""

            if 'dist-tags' in data:
                dist_tags = data["dist-tags"]
            else:
                dist_tags = ""

            if 'description' in data:
                description = data["description"]
            else:
                description = ""

            if 'author' in data:
                author = data["author"]
            else:
                author = []

            if 'license' in data:
                license = data["license"]
            else:
                license = []

            if 'readme' in data:
                readme = data["readme"]
            else:
                readme = ''

            i = 0
            results_json = {}
            results_json['versions'] = {}

            results_json['name'] = p_name
            results_json['dist-tags'] = dist_tags
            results_json['description'] = description
            results_json['author'] = author
            results_json['license'] = license
            results_json['readme'] = readme

            if not os.path.exists("/mnt/niahdb/niah-advisor/niah_pack/%s/%s" % (ecosystem, p_name)):
                os.mkdir("/mnt/niahdb/niah-advisor/niah_pack/%s/%s" % (ecosystem, p_name))

            cmd = "sudo chmod 777 /mnt/niahdb/niah-advisor/niah_pack/%s/%s" % (ecosystem, p_name)
            output = getoutput(cmd)


            sorted_key_value = sorted(data["versions"], key=lambda k: k, reverse=True)
            for key_data in sorted_key_value:
                info = data["versions"][key_data]

                results_json['versions'][key_data] = {}

                if 'name' in info:
                    verName = info["name"]
                else:
                    verName = ""

                if 'version' in info:
                    version = info["version"]
                else:
                    version = ""

                if 'description' in info:
                    verDescription = info["description"]
                else:
                    verDescription = ""

                if 'license' in info:
                    verLicense = info["license"]
                else:
                    verLicense = []

                if 'author' in info:
                    verAuthor = info["author"]
                else:
                    verAuthor = []

                dependencies = []

                if 'dependencies' in info:
                    for k, v in info['dependencies'].items():
                        res = {}
                        res['package'] = k
                        res['version'] = v
                        dependencies.append(res)

                if '_nodeVersion' in info:
                    nodeVersion = info["_nodeVersion"]
                else:
                    nodeVersion = {}

                if '_npmVersion' in info:
                    npmVersion = info["_npmVersion"]
                else:
                    npmVersion = {}

                if 'dist' in info:
                    dist = info["dist"]
                else:
                    dist = {}

                results_json['versions'][key_data]["name"] = verName
                results_json['versions'][key_data]["version"] = version
                results_json['versions'][key_data]["description"] = verDescription
                results_json['versions'][key_data]["license"] = verLicense
                results_json['versions'][key_data]["author"] = verAuthor
                results_json['versions'][key_data]["dependencies"] = dependencies
                results_json['versions'][key_data]["nodeVersion"] = nodeVersion
                results_json['versions'][key_data]["npmVersion"] = npmVersion
                results_json['versions'][key_data]["dist"] = dist

            results_json['current'] = results_json['versions'][sorted_key_value[0]]

            with open("/mnt/niahdb/niah-advisor/niah_pack/%s/%s/%s.json" % (ecosystem, p_name, p_name), "w") as outfile:
                json.dump(data ,outfile, indent=2)
            
            pack_datails = {}
            pack_datails['pack_info'] = data
            pack_datails['repo_info'] = {}
            pack_datails['vuln_report'] = {}

        except:
            pass
            # print(f"HTTPError: HTTP Error 404: Not Found : {url}")
            # print(data)

        return pack_datails

    def scan_hex(self, ecosystem, package):
        pack_url = "https://hex.pm/packages/%s" % package
        r = requests.get(pack_url)
        htmlContent = r.content
        soup = BeautifulSoup(htmlContent, "html.parser")
            
        version_url = pack_url + '/versions'
        r = requests.get(version_url)
        versionContent = r.content
        versionsoup = BeautifulSoup(versionContent, "html.parser")
            
        versions = []
        vlist = versionsoup.find('div',class_ = 'version-list')
        for a in vlist.findAll('li'):
            ver = a.find('a').text.strip()
            versions.append(ver)

        dependencies = []
        dep = soup.find('div', class_='col-md-9 no-padding').findAll('div',class_='col-md-11 with-divider no-padding')[2].findAll('div',class_ = 'col-md-6 no-padding')[1]
        for a in dep.findAll('li'):
            dep1 = a.find('a').text.strip()
            dependencies.append(dep1)

        p_name = soup.find('div', class_='container package-view').find('a').text

        p_dis = ''
        if soup.find('div',class_ = "description with-divider"):
            if soup.find('div',class_ = "description with-divider").find('p'):
                p_dis = soup.find('div',class_ = "description with-divider").find('p').text

        download1 = soup.find('div', class_='stats package-stats clearfix').findAll('span', class_='count-info no-wrap')[1]
        down1 = download1.text.strip()

        download7 = soup.find('div', class_='stats package-stats clearfix').findAll('span', class_='count-info no-wrap')[2]
        down7 = download7.text.strip()

        downloadall = soup.find('div', class_='stats package-stats clearfix').findAll('span', class_='count-info no-wrap')[3]
        downall = downloadall.text.strip()

        downloads = ({"yesterday:": down1, "last 7 day :": down7, "all time:": downall})
        latest_version = soup.find('span', class_="version").text

        if soup.find('span', class_="license"):
            license = soup.find('span', class_="license").text
        else:
            license = ''

        github_url = soup.find('div',class_='col-md-9 no-padding').find('div',class_='col-md-11 with-divider no-padding')
        g_url = ''
        if len(github_url.findAll('li')) > 1:
            for anchor in github_url.findAll('li')[1]:
                g_url = anchor.get('href')

        data = {}
        data['packagename'] = p_name
        data['description'] = p_dis
        data['latest_version'] = latest_version
        data['versions'] = versions
        data['license'] = license
        data['Dependencies'] = dependencies
        data['github_url'] = g_url
        data['downloads'] = downloads

        
        with open("/mnt/niahdb/niah-advisor/niah_pack/%s/%s/%s.json" % (ecosystem, p_name, p_name), "w") as outfile:
            json.dump(data ,outfile, indent=2)

        pack_datails = {}
        pack_datails['pack_info'] = data
        pack_datails['repo_info'] = self.get_github_repo_info(g_url)
        pack_datails['vuln_report'] = {}

        sbom_name = "/mnt/niahdb/niah-advisor/niah_pack/%s/%s/sbom/%s_latest_sbom.json" % (ecosystem, p_name, p_name)
        repo = str(g_url).split("/")[-1]
        try:

            os.chdir("repos")

            cmd = "GIT_ASKPASS=echo git clone %s.git" % g_url
            print(cmd)
            status, output = getstatusoutput(cmd)
            
            cmd = "sudo /usr/local/bin/syft packages dir:%s -o cyclonedx-json=%s" % (repo, sbom_name)
            print(cmd)
            status, output = getstatusoutput(cmd)

            cmd = "sudo rm -rf %s" % repo
            print(cmd)
            status, output = getstatusoutput(cmd)

            os.chdir("..")

        except:
            pass

        return pack_datails
    

    def scan_nuget(self, ecosystem, package):
        pack_url = "https://www.nuget.org/packages/%s" % package

        r = requests.get(pack_url)
        htmlContent = r.content
        soup = BeautifulSoup(htmlContent, "html.parser")
        data = {}
        try:
            p_name = soup.find('div', class_='package-title').find('span', class_='title').text.strip()
            print("packagename - %s" % p_name)
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

            pro_web = soup.find('ul', class_="list-unstyled ms-Icon-ul sidebar-links").findAll('li')[1].find('a').get('href')

            source_repo = soup.find('ul', class_="list-unstyled ms-Icon-ul sidebar-links").findAll('li')[2].find('a').get('href')

            license = soup.find('ul', class_="list-unstyled ms-Icon-ul sidebar-links").findAll('li')[3].find('a').text.strip()
            
            downloadurl = soup.find('ul', class_="list-unstyled ms-Icon-ul sidebar-links").findAll('li')[4].find('a').get('href')

            dependencies =[]
            try:
                dep = soup.find('div', id ='dependencies-tab').find('ul', id ='dependency-groups')
                for a in dep.findAll('a'):
                    dep1 = a.text.strip()
                    dependencies.append(dep1)
            except:
                dependencies = []

            downloadall = soup.find('div', class_="download-info").findAll('div', class_='download-info-row')[0].find('span',class_='download-info-content')
            downall = downloadall.text.strip()

            downloadcurrent = soup.find('div', class_="download-info").findAll('div', class_='download-info-row')[1].find('span',class_='download-info-content')
            downcurrent = downloadcurrent.text.strip()

            downloadavg = soup.find('div', class_="download-info").findAll('div', class_='download-info-row')[2].find('span',class_='download-info-content')
            downavg = downloadavg.text.strip()

            downloads = ({"Total Downloads:-": downall, "Current Version:-": downcurrent, "Per Day Average:-": downavg})

            data['packagename'] = p_name
            data['description'] = p_dis
            data['latest-version'] = latest_version
            data['versions'] = version_list
            data['project-website'] = pro_web
            data['Source-repo'] = source_repo
            data['license'] = license
            data['Dependencies'] = dependencies
            data['DownloadURL'] = downloadurl
            data['downloads'] = downloads


            repo = str(source_repo).split("/")[-1]
            try:

                os.chdir("repos")
                sbom_name = "/mnt/niahdb/niah-advisor/niah_pack/%s/%s/sbom/%s_latest_sbom.json" % (ecosystem, p_name, p_name)
                cmd = "GIT_ASKPASS=echo git clone %s.git" % source_repo
                print(cmd)
                status, output = getstatusoutput(cmd)
                print(os.listdir())
                
                cmd = "sudo /usr/local/bin/syft packages dir:%s -o cyclonedx-json=%s" % (repo, sbom_name)
                print(cmd)
                status, output = getstatusoutput(cmd)

                cmd = "sudo rm -rf %s" % repo
                print(cmd)
                status, output = getstatusoutput(cmd)
                
                # sboms.append(p_name)

                os.chdir("..")

            except:
                pass


            with open("/mnt/niahdb/niah-advisor/niah_pack/%s/%s/%s.json" % (ecosystem, p_name, p_name), "w") as outfile:
                json.dump(data ,outfile, indent=2)

            pack_datails = {}
            pack_datails['pack_info'] = data
            pack_datails['repo_info'] = self.get_github_repo_info(source_repo)
            pack_datails['vuln_report'] = {}

            
        except:
            print(f"HTTPError: HTTP Error 404: Not Found : {pack_url}")


        return pack_datails
    

    def scan_pub(self, ecosystem, package):

        pack_url = "https://pub.dev/packages/%s" % package
        page = requests.get(pack_url)
        response = page.content
        soup = BeautifulSoup(response,"html.parser")
        version_url = pack_url + '/versions'
        
        r = requests.get(version_url)
        versionContent = r.content
        versionsoup = BeautifulSoup(versionContent, "html.parser")

        versions = []

        vlist = versionsoup.find('table', class_ = 'version-table').find('tbody')

        for table in vlist.findAll('tr'):
            ver = table.find('td').find('a').text
            versions.append(ver)
            
        l_version = versions[0]

        package_name = re.findall(r'https:\/\/pub.dev\/packages\/(.*)',str(pack_url))[0]

        div = soup.find('div', class_ = 'detail-container').find('div', class_ = 'detail-tags')

        sdk_types = []
        if div.find('div', class_ = '-pub-tag-badge'):
            sdk_type = div.find('div', class_ = '-pub-tag-badge').findAll('a')
            for sdk in sdk_type:
                sdk_types.append(sdk.text)

        a_tag = soup.find('aside', class_ = 'detail-info-box').find('a')

        try:
            likes = a_tag.find('div', class_ = 'packages-score packages-score-like').text.replace("likes", "")
        except:
            likes = ''

        pub_points = a_tag.find('div', class_ = 'packages-score packages-score-health').text.replace("pub points", "")

        popularity = a_tag.find('div', class_ = 'packages-score packages-score-popularity').text.replace("%popularity", "")

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

        result = {}
        result['package_name'] = package_name
        result['sdk'] = sdk_types
        result['likes'] = likes
        result['points'] = pub_points
        result['populirity'] = popularity
        result['description'] = des
        result['version'] = versions
        result['latest_version'] = l_version
        result['github_url'] = git_link
        result['home_url'] = home_url
        result['license'] = lic
        result['dependencies'] = depends

        # print(git_link)
        # if git_link is not "":
        #     gits.append(package_name)

        print(result)

        pack_datails = {}
        pack_datails['pack_info'] = result
        pack_datails['repo_info'] = {}
        pack_datails['vuln_report'] = {}
        

        with open("/mnt/niahdb/niah-advisor/niah_pack/%s/%s/%s.json" % (ecosystem, package_name, package_name), "w") as outfile:
            json.dump(result ,outfile, indent=2)


        return pack_datails
    


    def scan_crates(self, ecosystem, package):

        pack_url = 'https://crates.io/api/v1/crates/%s' % package
        print(pack_url)
        response = requests.get(pack_url)
        jsondata  = response.json()


        latest_version = jsondata['crate']['newest_version']
        dep_url = 'https://crates.io/api/v1/crates/%s/%s/dependencies' % (package, latest_version)
        # print(dep_url)
        dep = requests.get(dep_url)
        dependency = dep.json()
        if 'dependency' in dependency:
            jsondata['crate']['dependencies'] = dependency
        else:
            jsondata['crate']['dependencies'] = {}


        git_repo = jsondata['crate']['repository']


        repo = str(git_repo).split("/")[-1]
        try:

            os.chdir("repos")
            sbom_name = "/mnt/niahdb/niah-advisor/niah_pack/%s/%s/sbom/%s_latest_sbom.json" % (ecosystem, package, package)
            cmd = "GIT_ASKPASS=echo git clone %s.git" % git_repo
            print(cmd)
            status, output = getstatusoutput(cmd)
            print(os.listdir())
            
            cmd = "sudo /usr/local/bin/syft packages dir:%s -o cyclonedx-json=%s" % (repo, sbom_name)
            print(cmd)
            status, output = getstatusoutput(cmd)

            cmd = "sudo rm -rf %s" % repo
            print(cmd)
            status, output = getstatusoutput(cmd)
            

            os.chdir("..")

        except:
            pass
            
        pack_datails = {}
        pack_datails['pack_info'] = jsondata
        pack_datails['repo_info'] = self.get_github_repo_info(git_repo)
        pack_datails['vuln_report'] = {}

        with open("/mnt/niahdb/niah-advisor/niah_pack/%s/%s/%s.json" % (ecosystem, package, package), "w") as outfile:
            json.dump(jsondata ,outfile, indent=2)

        return pack_datails
    

    def scan_composer(self, ecosystem, package):
        url = "https://repo.packagist.org/p2/%s.json" % package

        print(url)
        try:
            response = urllib.request.urlopen(url)
            pack_data = json.load(response)

            print(pack_data)

            p_name = str(package).replace("/", "_")

            file_name = "/mnt/niahdb/niah-advisor/niah_pack/%s/%s/%s.json" % (package, p_name, p_name)
            print(file_name)
            sbom_name = "/mnt/niahdb/niah-advisor/niah_pack/%s/%s/%s_latest_sbom.json" % (package, p_name, p_name)

            with open(file_name, "w") as outfile:
                json.dump(pack_data ,outfile, indent=2)

            pack_datails = {}
            pack_datails['pack_info'] = pack_data
            pack_datails['repo_info'] = {}
            pack_datails['vuln_report'] = {}


            if "packages" in pack_data:
                if "%s" % package in pack_data["packages"]:
                    if "homepage" in pack_data["packages"][package][0]:
                        github_url = pack_data["packages"][package][0]["homepage"]
                        pack_datails['repo_info'] = self.get_github_repo_info(github_url)

                        print("------------", github_url)
        #                     github_url = pack_info['project_urls']['Homepage']

                        repo = str(github_url).split("/")[-1]
                        try:

                            os.chdir("repos")

                            cmd = "GIT_ASKPASS=echo git clone %s.git" % github_url
                            print(cmd)
                            status, output = getstatusoutput(cmd)
                            print(os.listdir())
                            
                            cmd = "sudo /usr/local/bin/syft packages dir:%s -o cyclonedx-json=%s" % (repo, sbom_name)
                            print(cmd)
                            status, output = getstatusoutput(cmd)

                            cmd = "sudo rm -rf %s" % repo
                            print(cmd)
                            status, output = getstatusoutput(cmd)
                            
                            os.chdir("..")

                        except:
                            pass
                    else:
                        print("Code not available")
                else:
                    print("project_urls not available")
            else:
                print("info not available") 
        except:
            print(f"HTTPError: HTTP Error 404: Not Found : {url}")

        return pack_datails




    def get_pack_details(self, ecosystem, package):
        
        if ecosystem == "pypi":
            pack_datails = self.scan_pypi(ecosystem, package)
            return pack_datails

        if ecosystem == "ruby":
            pack_datails = self.scan_ruby(ecosystem, package)
            return pack_datails

        if ecosystem == "npm":
            pack_datails = self.scan_npm(ecosystem, package)
            return pack_datails

        if ecosystem == "hex":
            pack_datails = self.scan_hex(ecosystem, package)
            return pack_datails

        if ecosystem == "nuget":
            pack_datails = self.scan_nuget(ecosystem, package)
            return pack_datails

        if ecosystem == "pub":
            pack_datails = self.scan_pub(ecosystem, package)
            return pack_datails

        if ecosystem == "crates":
            pack_datails = self.scan_crates(ecosystem, package)
            return pack_datails

        if ecosystem == "composer":
            pack_datails = self.scan_composer(ecosystem, package)


if __name__ == "__main__":
   

    res = niah_advisor_scan()
    ecosystem = "pypi"
    package = "urllib3"

    res.get_pack_details(ecosystem, package)
    


