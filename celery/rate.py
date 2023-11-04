import requests

headers = {
    'Accept': 'application/vnd.github+json',
    'Authorization': 'Bearer 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',
    'X-GitHub-Api-Version': '2022-11-28',
}

response = requests.get('https://api.github.com/rate_limit', headers=headers)

print(response.json())
