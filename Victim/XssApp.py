import Logger
import os
from flask import Flask, request
from Classifier import ThreatClassifier
from Request.Request import Request, interesting_header_list

app = Flask(__name__)
CLF = ThreatClassifier()
LOGGER = Logger.init_logging('XssApp', 'Victim')
WAF_URL = os.getenv('WAF_URL') if os.getenv('WAF_URL') else 'http://127.0.0.1:8000/waf'


def flask_request_to_model_input(req: request) -> Request:
    header_interesting_fields = interesting_header_list()
    
    # clean http body
    request_body = req.form.to_dict()
    body = ""
    for key in request_body:
        body += f"{key}={request_body[key]}&"
    body = body[:-1]
    
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


# NO FIREWALL
@app.route('/api/v1/hello/<string:name>', methods=['GET', 'POST'])
def hello(name):
    LOGGER.info('Request: %s', request)
    return 'Hello, ' + name + '!'


# WITH FIREWALL
@app.route('/api/v1/hello-wh-waf/<string:name>', methods=['GET', 'POST'])
def hello_wh_waf(name):
    LOGGER.info('Request: %s', request)
    req = flask_request_to_model_input(request)
    req = CLF.classify_request(req)
    
    if len(req.threats) != 0 and 'valid' not in req.threats:
        LOGGER.info('Threats detected: %s', req.threats)
        LOGGER.info('Request blocked')
        return 'Forbidden', 403

    # good request
    # return the response
    return 'Hello, ' + name + '!'


if __name__ == '__main__':
    app.run(debug=True, host='127.0.0.1', port=8000)
