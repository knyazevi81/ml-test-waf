""""
Flask app that acts as a Web Application Firewall (WAF) for the web server.
"""
from flask import Flask, request, jsonify
from Sniffer.Request import Request
from Classifier import ThreatClassifier

app = Flask(__name__)
classifier = ThreatClassifier()

@app.route('/waf', methods=['POST'])
def waf():
    """
    Endpoint for the WAF to classify the threat type from the request
    """
    if request.method == 'POST':
        data = request.get_json()
        req = Request(**data)
        req = classifier.classify_request(req)
        return jsonify(req.to_json())

if __name__ == '__main__':
    app.run(debug=True, host='127.0.0.1', port=8000)
    