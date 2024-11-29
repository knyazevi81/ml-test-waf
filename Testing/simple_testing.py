import requests
import json

with open('testing_app.json', 'r') as f:
    reqs_app = json.load(f)

with open('testing_waf.json', 'r') as f:
    reqs_wh_waf = json.load(f)

if __name__ == '__main__':
    # test the APP
    for req in reqs_app:
        requests.request(**req)
    
    # test the WAF
    for req in reqs_wh_waf:
        requests.request(**req)
