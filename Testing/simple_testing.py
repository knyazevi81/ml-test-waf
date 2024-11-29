import requests
import json

with open('testing_waf.json', 'r') as f:
    reqs = json.load(f)

if __name__ == '__main__':
    for req in reqs:
        requests.request(**req)
