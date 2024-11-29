import json

class Request(object):
    def __init__(self, id_: int = None, 
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
    

# use for feature extraction   
def interesting_header_list():
    return ['Http_Version',
            'A_IM',
            'Accept',
            'Accept_Charset',
            'Accept_Datetime',
            'Accept_Encoding',
            'Accept_Language',
            'Access_Control_Request_Headers',
            'Access_Control_Request_Method',
            'Authorization',
            'Cache_Control',
            'Connection',
            'Content_Length',
            'Content_MD5',
            'Content_Type',
            'Cookie',
            'DNT',
            'Date',
            'Expect',
            'Forwarded',
            'From',
            'Front_End_Https',
            'If_Match',
            'If_Modified_Since',
            'If_None_Match',
            'If_Range',
            'If_Unmodified_Since',
            'Keep_Alive',
            'Max_Forwards',
            'Origin',
            'Permanent',
            'Pragma',
            'Proxy_Authorization',
            'Proxy_Connection',
            'Range',
            'Referer',
            'Save_Data',
            'TE',
            'Upgrade',
            'Upgrade_Insecure_Requests',
            'User_Agent',
            'Via',
            'Warning',
            'X_ATT_DeviceId',
            'X_Correlation_ID',
            'X_Csrf_Token',
            'X_Forwarded_For',
            'X_Forwarded_Host',
            'X_Forwarded_Proto',
            'X_Http_Method_Override',
            'X_Request_ID',
            'X_Requested_With',
            'X_UIDH',
            'X_Wap_Profile']
