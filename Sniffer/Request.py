import json

class Request(object):
    def __init__(self, id_=None, 
                 timestamp: str = None, 
                 origin: str = None, 
                 host: str = None, 
                 request: str = None, 
                 body: str = None, 
                 method: str = None, 
                 headers: dict = None, 
                 threats: dict = None):
        self.id = id_
        self.timestamp = timestamp
        self.origin = origin    # IP address of the client that made the request
        self.host = host        # IP address of the protected server
        self.request = request  # URL requested
        self.body = body        # Body of the request
        self.method = method    # HTTP method
        self.headers = headers  # HTTP headers
        self.threats = threats  # Threats detected

    def to_json(self):
        output = {}
        if self.request is not None and self.request != '':
            output['request'] = self.request
        if self.body is not None and self.body != '':
            output['body'] = self.body
        if self.headers is not None:
            for header, value in self.headers.items():
                output[header] = value
        return json.dumps(output)
