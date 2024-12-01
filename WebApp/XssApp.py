import Logger
from flask import Flask, request
from flask_cors import CORS

app = Flask(__name__)
LOGGER = Logger.init_logging('XssApp', 'WebApp')
CORS(app)


# NO FIREWALL - This route is vulnerable to XSS
@app.route('/api/v1/hello/<string:name>', methods=['GET', 'POST'])
def hello(name):
    LOGGER.info('Request: %s', request)
    return 'Hello, ' + name + '!'


if __name__ == '__main__':
    app.run(debug=True, host='127.0.0.1', port=8001)
