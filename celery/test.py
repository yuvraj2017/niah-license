import requests
import base64
import json

def get_github_readme(owner, repo):

    api_url = f"https://api.github.com/repos/{owner}/{repo}/readme"

    print(api_url)
    

    response = requests.get(api_url)
    print(response.status_code)
    
    if response.status_code == 200:
        data = response.json()
        readme_content = base64.b64decode(data["content"]).decode("utf-8")
        return readme_content
    else:
        return None


owner = "urllib3"
repo = "urllib3"

readme = get_github_readme(owner, repo)

print(readme)

# with open("readme.json")


