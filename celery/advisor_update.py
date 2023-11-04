import os
import json


repos = ["pypi", "composer", "crates", "ruby", "hex", "pub"]

# repos = ["hex"]

update_list = {}

for repo in repos:
    update_list[repo] = {}

    with open("/mnt/niahdb/niah-advisor/niah_pack/%s_update.json" % repo, "r") as f:
        package_list = json.load(f)

        for package in package_list:

            if repo == "pypi":

                with open("/mnt/niahdb/niah-advisor/niah_pack/%s/%s/%s.json" % (repo, package, package), "r") as f:
                    pack_data = json.load(f)

                update_list[repo][package] = {}
                update_list[repo][package]["p_name"] = pack_data['info']['name']
                update_list[repo][package]["latest_version"] = pack_data['info']['version']
                update_list[repo][package]["description"] = pack_data['info']['summary']

            if repo == "hex":

                with open("/mnt/niahdb/niah-advisor/niah_pack/%s/%s/%s.json" % (repo, package, package), "r") as f:
                    pack_data = json.load(f)

                update_list[repo][package] = {}
                update_list[repo][package]["p_name"] = pack_data['packagename']
                update_list[repo][package]["latest_version"] = pack_data['latest_version']
                update_list[repo][package]["description"] = pack_data['description']

            if repo == "pub":

                with open("/mnt/niahdb/niah-advisor/niah_pack/%s/%s/%s.json" % (repo, package, package), "r") as f:
                    pack_data = json.load(f)
                    pack_data = eval(pack_data)

                    print(type(pack_data))

                update_list[repo][package] = {}
                update_list[repo][package]["p_name"] = pack_data['package_name']
                update_list[repo][package]["latest_version"] = pack_data['latest_version']
                update_list[repo][package]["description"] = pack_data['description']

            if repo == "composer":
                print(package)
                package = str(package).replace("/", "_")

                file_path = "/mnt/niahdb/niah-advisor/niah_pack/%s/%s/%s.json" % (repo, package, package)
                if os.path.exists(file_path):
                    with open(file_path, "r") as f:
                        pack_data = json.load(f)

                    slash_pack = str(package).replace("_", "/")
                    com_package = pack_data['packages'][slash_pack][0]

                    update_list[repo][package] = {}
                    update_list[repo][package]["p_name"] = com_package['name']
                    update_list[repo][package]["latest_version"] = com_package['version']
                    update_list[repo][package]["description"] = com_package['description']

            if repo == "crates":
                
                just_updated = package_list['just_updated']
                new_crates = package_list['new_crates']

                for crate in just_updated:
                    package = crate['name']
                    newest_version = crate['newest_version']
                    description = crate['description']

                    update_list[repo][package] = {}
                    update_list[repo][package]["p_name"] = package
                    update_list[repo][package]["latest_version"] = newest_version
                    update_list[repo][package]["description"] = description

                for crate in new_crates:
                    package = crate['name']
                    newest_version = crate['newest_version']
                    description = crate['description']

                    update_list[repo][package] = {}
                    update_list[repo][package]["p_name"] = package
                    update_list[repo][package]["latest_version"] = newest_version
                    update_list[repo][package]["description"] = description


            if repo == "ruby":
                
                for item in package_list:
                    package = item['packagename']
                    latest_version = item['latest_version']
                    description = item['description']

                    update_list[repo][package] = {}
                    update_list[repo][package]["p_name"] = package
                    update_list[repo][package]["latest_version"] = latest_version
                    update_list[repo][package]["description"] = description




with open("/home/niah/niah-license/advisor_updates.json", "w") as outfile:
    json.dump(update_list, outfile, indent=2)

      