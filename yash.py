import glob
import json
import os



results = {}
package = 'ytfzf'

file_path = next(glob.iglob("/mnt/niahdb/packagesdb/platforms/debian/**/%s/%s.json" % (package,package), recursive=True), "")

print(file_path)

with open (file_path, "r") as f:
    jsondata = json.load(f)

    print(jsondata)

    print("======================")


    if 'current' in jsondata:
        results['author'] = ""
        results['description'] = ""
        if 'description' in jsondata['current']:
            results['description'] = jsondata['current']['description']

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


        # if check:
        #     results = {}
        #     results['author'] = ""
        #     results['description'] = ""
        #     if 'description' in jsondata['current']:
        #         results['description'] = jsondata['current']['description']

        #     if 'source_url' in jsondata['current']:
        #         results['home_page'] = jsondata['current']['source_url']

        #     results['license'] = ""
        #     results['package_url'] = ""
        #     if 'source_url' in jsondata['current']:
        #         results['package_url'] = jsondata['current']['source_url']
            
        #     results['requires_dist'] = ""

        #     if 'dependencies' in jsondata['current']:
        #         results['requires_version'] = jsondata['current']['dependencies']
        #     results['version'] = ""
        #     if 'pkg_version' in jsondata['current']:
        #         results['version'] = jsondata['current']['pkg_version']

        #     results['releases'] = ""

                    
      

    print(results)

# if file_path:
#     print("File path:", file_path)
#     file_path_with_name = os.path.join(file_path, "%s.json" % package)
#     with open(file_path_with_name, "r") as file:
#         jsondata = json.load(file)
#         print(jsondata)
# else:
#     print("File not found.")