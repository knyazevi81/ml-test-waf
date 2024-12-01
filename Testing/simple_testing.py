import requests
import json
import time

with open('testing_app.json', 'r') as f:
    reqs_app = json.load(f)

with open('testing_waf.json', 'r') as f:
    reqs_wh_waf = json.load(f)

if __name__ == '__main__':
    print('Testing the applications')
    time.sleep(3)
    # test the APP
    for req in reqs_app:
        print(req)
        response = requests.request(**req)
        print(response.text)
    print()
    print('Testing the WAF')
    time.sleep(3)
    # test the WAF
    for req in reqs_wh_waf:
        print(req)
        response = requests.request(**req)
        print(response.text)
