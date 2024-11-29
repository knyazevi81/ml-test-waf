from flask import Flask, request, jsonify
from Sniffer.Request import Request
import requests
import Logger
import json

app = Flask(__name__)
LOGGER = Logger.init_logging('rest_app', 'Victim')

@app.route('/api/v1/hello/<string:name>', methods=['GET', 'POST'])
def hello(name):
    return 'Hello, ' + name + '!'

@app.route('/api/v1/hello-wh-waf/<string:name>', methods=['GET', 'POST'])
def hello_wh_waf(name):
    # send to waf endpoint to classify the threat type
    request_data = {
        'origin': request.remote_addr,
        'host': request.host,
        'request': request.data.decode('utf-8'),
        'method': request.method,
        'headers': dict(request.headers)
    }
    req = Request(**request_data)
    response = requests.post('http://127.0.0.1:8000/waf', json=json.loads(req.to_json()))
    if response.status_code == 200:
        req = Request(**response.json())
        if len(req.threats) != 0 and 'valid' not in req.threats:
            LOGGER.info('Threats detected: %s', req.threats)
            LOGGER.info('Request: %s', req.to_json())
            return

    # good request
    # return the response
    return 'Hello, ' + name + '!'


if __name__ == '__main__':
    app.run(debug=True, host='127.0.0.1', port=8001)
