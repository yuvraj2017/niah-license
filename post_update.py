import json
import os


# Ubuntu
with open("/var/DB/feeds/platform/ubuntu/ubuntu.json", "r") as f:
    ubuntu = json.load(f)

ubuntu_db = {}
ubuntu_db['data'] = []
for osname in ubuntu:
    for db in ubuntu[osname]:
        ubuntu_db['data'].append(db)

with open("/var/DB/feeds/platform/ubuntu/db_ubuntu.json", "w") as outfile:
    json.dump(ubuntu_db, outfile, indent=2)

# Debian

with open("/var/DB/feeds/platform/debian/debian.json", "r") as f:
    debian = json.load(f)

debian_db = {}
debian_db['data'] = []
for osname in debian:
    for db in debian[osname]:
        debian_db['data'].append(db)

with open("/var/DB/feeds/platform/debian/db_debian.json", "w") as outfile:
    json.dump(debian_db, outfile, indent=2)

# RHEL
with open("/var/DB/feeds/platform/rhel/rhel.json", "r") as f:
    rhel = json.load(f)

rhel_db = {}
rhel_db['data'] = []
for osname in rhel:
    for db in rhel[osname]:
        rhel_db['data'].append(db)

with open("/var/DB/feeds/platform/rhel/db_rhel.json", "w") as outfile:
    json.dump(rhel_db, outfile, indent=2)

# Oracle
with open("/var/DB/feeds/platform/oracle/oracle.json", "r") as f:
    oracle = json.load(f)

oracle_db = {}
oracle_db['data'] = []
for osname in oracle:
    for db in oracle[osname]:
        oracle_db['data'].append(db)

with open("/var/DB/feeds/platform/oracle/db_oracle.json", "w") as outfile:
    json.dump(oracle_db, outfile, indent=2)

print("completed")