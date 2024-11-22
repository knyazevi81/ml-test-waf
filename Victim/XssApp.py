from flask import Flask
import Logger

app = Flask(__name__)
LOGGER = Logger.init_logging('rest_app', 'Victim')

@app.route('/api/v1/hello/<string:name>', methods=['GET', 'POST'])
def hello(name):
    LOGGER.info(f"injected: {name}")
    return 'Hello, ' + name + '!'

if __name__ == '__main__':
    app.run(debug=True)
