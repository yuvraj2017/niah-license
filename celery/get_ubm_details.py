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

if not os.path.exists("/home/niah/extra/niah_pack"):
    os.mkdir("/home/niah/extra/niah_pack")

if not os.path.exists("/home/niah/extra/repos"):
    os.mkdir("/home/niah/extra/repos")





def scan_ubuntu():

    data_dir = "/mnt/niahdb/packagesdb/platforms"

    os.chdir(data_dir)
    sboms = []
    platform_list = os.listdir(data_dir)

    for platform in platform_list:

        if not os.path.exists("/home/niah/extra/niah_pack/%s" % platform):
            os.mkdir("/home/niah/extra/niah_pack/%s" % platform)
        
        platform_path = "%s/%s" % (data_dir, platform)

        print(platform_path)
        if platform in ['ubuntu', 'debian']:
            os_list = os.listdir(platform_path)

            for os_item in os_list:
                os_path = "%s/%s" % (platform_path, os_item)
                # print("111111", len(os_path))

                pack_list = os.listdir(os_path)
                for pack in pack_list:
                    pack_path = "%s/%s" % (os_path, pack)

                    # print("======", len(pack_path))

                    # pack_files = os.listdir(pack_path)

                    file_name = "/mnt/niahdb/packagesdb/platforms/%s/%s/%s/%s.json" % (platform, os_item, pack, pack)
                    print(file_name)

                    try:
                        with open(file_name, "r") as f:
                            json_data = json.load(f)


                        if not os.path.exists("/home/niah/extra/niah_pack/%s/%s" % (platform, pack)):
                            os.mkdir("/home/niah/extra/niah_pack/%s/%s" % (platform, pack))


                        with open("/home/niah/extra/niah_pack/%s/%s/%s.json" % (platform, pack, pack), "w") as outfile:
                            json.dump(json_data ,outfile, indent=2)
                    except:
                        print("Invalid file")
        
        elif platform == "suse":
            file_list = os.listdir(platform_path)

            for file in file_list:
                with open("/mnt/niahdb/packagesdb/platforms/suse/%s" % file, "r") as f:
                    try:
                        suse_data = json.load(f)
                        package = str(file).replace(".json", "")

                        if not os.path.exists("/home/niah/extra/niah_pack/%s/%s" % (platform, package)):
                            os.mkdir("/home/niah/extra/niah_pack/%s/%s" % (platform, package))

                        cmd = "sudo chmod 777 /home/niah/extra/niah_pack/%s/%s" % (platform, package)
                        output = getoutput(cmd)

                        with open("/home/niah/extra/niah_pack/%s/%s/%s.json" % (platform, package, package), "w") as outfile:
                            json.dump(suse_data ,outfile, indent=2)

                        
                        github_url = suse_data['data'][0]['home_page']

                        print(github_url)
                        sbom_name = "/home/niah/extra/niah_pack/%s/%s/%s_latest_sbom.json" % (platform, package, package)

                        if "github" in str(github_url):
                            repo = str(github_url).split("/")[-1]
                            try:

                                os.chdir("repos")

                                cmd = "GIT_ASKPASS=echo git clone %s.git" % github_url
                                print(cmd)
                                status, output = getstatusoutput(cmd)
                                
                                cmd = "sudo /usr/local/bin/syft packages dir:%s -o cyclonedx-json=%s" % (repo, sbom_name)
                                print(cmd)
                                status, output = getstatusoutput(cmd)

                                sboms.append(package)

                                cmd = "sudo rm -rf %s" % repo
                                print(cmd)
                                status, output = getstatusoutput(cmd)

                                os.chdir("..")

                            except:
                                pass

                
                    except:
                        pass
                
                print("================================================", len(sboms), "================================================")

                




            print("\n\n\n\n\n\n\n\n\n\n\n\n\n\n", pack_list ,"\n\n\n\n\n\n\n\n\n\n\n\n\n\n", len(pack_list))







# eco_list = ['ubuntu', 'debian', 'maven']
# eco_list = ['ubuntu']

# for eco_name in eco_list:
    
#     if eco_name == "ubuntu":
#         if not os.path.exists("/home/niah/extra/niah_pack/%s" % eco_name):
#             os.mkdir("/home/niah/extra/niah_pack/%s" % eco_name)
#         scan_ubuntu()

    # if eco_name == "ruby":
    #     if not os.path.exists("/home/niah/extra/niah_pack/%s" % eco_name):
    #         os.mkdir("/home/niah/extra/niah_pack/%s" % eco_name)
    #     scan_ruby()

    # if eco_name == "npm":
    #     if not os.path.exists("/home/niah/extra/niah_pack/%s" % eco_name):
    #         os.mkdir("/home/niah/extra/niah_pack/%s" % eco_name)
    #     scan_npm()

    # if eco_name == "hex":
    #     if not os.path.exists("/home/niah/extra/niah_pack/%s" % eco_name):
    #         os.mkdir("/home/niah/extra/niah_pack/%s" % eco_name)
    #     scan_hex()

    # if eco_name == "nuget":
    #     if not os.path.exists("/home/niah/extra/niah_pack/%s" % eco_name):
    #         os.mkdir("/home/niah/extra/niah_pack/%s" % eco_name)
    #     scan_nuget()

    # if eco_name == "pub":
    #     if not os.path.exists("/home/niah/extra/niah_pack/%s" % eco_name):
    #         os.mkdir("/home/niah/extra/niah_pack/%s" % eco_name)
    #     scan_pub()

    # if eco_name == "crates":
    #     if not os.path.exists("/home/niah/extra/niah_pack/%s" % eco_name):
    #         os.mkdir("/home/niah/extra/niah_pack/%s" % eco_name)
    #     scan_crates()

    # if eco_name == "composer":
    #     if not os.path.exists("/home/niah/extra/niah_pack/%s" % eco_name):
    #         os.mkdir("/home/niah/extra/niah_pack/%s" % eco_name)
    #     scan_composer()



scan_ubuntu()
