import requests
import Logger
import os
from flask_cors import CORS
from flask import Flask, request, jsonify
from Classifier import ThreatClassifier
from Sniffer.Request import Request, interesting_header_list

app = Flask(__name__)
CLF = ThreatClassifier()
LOGGER = Logger.init_logging('Firewall', 'WebAppFirewall')
APP_URL = os.getenv('APP_URL') if os.getenv('APP_URL') else 'http://127.0.0.1:8001'
CORS(app)


def flask_request_to_model_input(req: request) -> Request:
    header_interesting_fields = interesting_header_list()
    
    # clean http body
    request_body = req.form.to_dict()
    body = ""
    for key in request_body:
        body += f"{key}={request_body[key]}&"
    body = body[:-1]
    
    # get query parameters
    query_parameters = req.args.to_dict()
    # add query parameters to the request path
    if len(query_parameters) != 0:
        req.path += '?'
        for key in query_parameters:
            req.path += f"{key}={query_parameters[key]}&"
        req.path = req.path[:-1]
    
    # clean http headers
    headers = dict()
    for field in header_interesting_fields:
        f = req.headers.get(field)
        if f is not None and f != 'None':
            headers[field] = f
    
    # create the model input
    request_data = {
        'origin': req.remote_addr,
        'host': req.host,
        'request': req.path,
        'body': body,
        'method': req.method,
        'headers': headers
    }
    model_input = Request(**request_data)
    return model_input


@app.route('/api/v1/hello-wh-waf/<name>', methods=['GET', 'POST'])
def hello_wh_waf(name):
    LOGGER.info('Request: %s', request)
    req = flask_request_to_model_input(request)
    req = CLF.classify_request(req)
    
    if len(req.threats) != 0 and 'valid' not in req.threats:
        # threat detected
        LOGGER.info('Threats detected: %s', req.threats)
        LOGGER.info('Request blocked')
        return 'Forbidden', 403

    # good request
    # return the response from the app
    endpoint = f'{APP_URL}/api/v1/hello/{name}'
    LOGGER.info('Request forwarded to the app: %s', endpoint)
    method = request.method
    if method == 'POST':
        data = request.form.to_dict()
        response = requests.post(endpoint,
                                 data=data,
                                 headers=request.headers,
                                 cookies=request.cookies,
                                 files=request.files,
                                 timeout=10,
                                 verify=False)
    else:
        response = requests.get(endpoint,
                                headers=request.headers,
                                cookies=request.cookies,
                                timeout=10,
                                verify=False)
    return response.text


if __name__ == '__main__':
    app.run(debug=True, host='127.0.0.1', port=8000)
