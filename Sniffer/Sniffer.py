import scapy.all as scapy
import urllib.parse
import Logger
import os
from scapy.all import sniff, Raw, ifaces
from scapy.layers.http import HTTPRequest, HTTP
from scapy.layers.inet import IP, TCP
from scapy.sessions import TCPSession
from argparse import ArgumentParser


LOGGER = Logger.init_logging('Sniffer', 'Sniffer')

LOGGER.info("Define arguments ...")
parser = ArgumentParser()
parser.add_argument('--port', type=int, default=8000, help='Defines which port to sniff')

LOGGER.info("Parse the arguments ...")
args = parser.parse_args()
LOGGER.info(f"port: {args.port}")

LOGGER.info("Binding ports for scapy ...")
# dport := destination port
# sport := source port
scapy.packet.bind_layers(TCP, HTTP, dport=args.port)
scapy.packet.bind_layers(TCP, HTTP, sport=args.port)

LOGGER.info("Initialize the database and classifiers ...")

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


import joblib
import urllib.parse
import json


class ThreatClassifier(object):
	def __init__(self):
		self.clf = joblib.load("C:/Users/khasa/OneDrive/Рабочий стол/ml-test-waf/Classifier/predictor.joblib")
		self.pt_clf = joblib.load("C:/Users/khasa/OneDrive/Рабочий стол/ml-test-waf/Classifier/pt_predictor.joblib")

    
	def __unquote(self, text):
		k = 0
		uq_prev = text
		while (k < 100):
			uq = urllib.parse.unquote_plus(uq_prev)
			if uq == uq_prev:
				break
			else:
				uq_prev = uq
		return uq_prev

	def __remove_new_line(self, text):
		text = text.strip()
		return ' '.join(text.splitlines())

	def __remove_multiple_whitespace(self, text):
		return ' '.join(text.split())

	def __clean_pattern(self, pattern):
		pattern = self.__unquote(pattern)
		pattern = self.__remove_new_line(pattern)
		pattern = pattern.lower()
		pattern = self.__remove_multiple_whitespace(pattern)

	def __is_valid(self, paramater):
		return paramater != None and paramater != ''

	def classify_request(self, req):
		if not isinstance(req, Request):
			raise TypeError("Object should be a Request!!!")
		
		paramaters = []
		locations = []

		if self.__is_valid(req.Request):
			paramaters.append(self.__clean_pattern(req.request))
			locations.append('Request')

		if self.__is_valid(req.body):
			paramaters.append(self.__clean_pattern(req.body))
			locations.append('Body')

		if 'Cookie' in req.headers and self.__is_valid(req.headers['Cookie']):
			paramaters.append(self.__clean_pattern(req.headers['Cookie']))
			locations.append('Cookie')

		if 'User_Agent' in req.headers and self.__is_valid(req.headers['User_Agent']):
			paramaters.append(self.__clean_pattern(req.headers['User_Agent']))
			locations.append('User Agent')

		if 'Accept_Encoding' in req.headers and self.__is_valid(req.headers['Accept_Encoding']):
			paramaters.append(self.__clean_pattern(req.headers['Accept_Encoding']))
			locations.append('Accept Encoding')

		if 'Accept_Language' in req.headers and self.__is_valid(req.headers['Accept_Language']):
			paramaters.append(self.__clean_pattern(req.headers['Accept_Language']))
			locations.append('Accept Language')

		req.threats = {}

		if len(paramaters) != 0:
			predictions = self.clf.predict(paramaters)
			for idx, pref in enumerate(predictions):
				if pred != 'valid':
					req.threats[pred] = locations[idx]

		request_paramaters = {}
		if self.__is_valid(req.request):
			request_paramaters = urllib.parse.parse_qs(self.__clean_pattern(req.request))

		body_paramaters = {}
		if self.__is_valid(req.request):
			body_paramaters = urllib.parse.parse_qs(self.__clean_pattern(req.body))

			if len(body_paramaters) == 0:
				try:
					body_paramaters = json.loads(self.__clean_pattern(req.body))
				except:
					pass

		paramaters = []
		locations = []

		for name, value in request_paramaters.items():
			for elem in value:
				paramaters.append([len(elem)])
				locations.append('Request')

		for name, value in body_paramaters.items():
			if isinstance(value, list):
				for elem in value:
					paramaters.append([len(elem)])
					locations.append('Body')
			else:
				paramaters.append([len(value)])
				locations.append('Body')

		if len(paramaters) != 0:
			pt_predictions = self.pt_clf.predict(paramaters)
			for idx, pred in enumerate(pt_predictions):
				if pred != 'valid':
					req.threats[pred] = locations[idx]

		if len(req.threats) == 0:
			req.threats['valid'] = ''

import datetime
import sqlite3
import pandas as pd
import json
import os


class DBController(object):
    def __init__(self):
        self.conn = sqlite3.connect("../logs/traffics.db")
        self.conn.row_factory = sqlite3.Row
    
    def save(self, obj: Request) -> None:
        if not isinstance(obj, Request):
            raise TypeError("Object should be a WAF.Request.Request!!!")
        
        # Save the request to the database
        cursor = self.conn.cursor()
        obj.timestamp = datetime.datetime.now()
        cursor.execute("INSERT INTO logs (timestamp, origin, host, request, method, body, headers) VALUES (?, ?, ?, ?, ?, ?, ?)",
                       (obj.timestamp, obj.origin, obj.host, obj.request, obj.method, obj.body, json.dumps(obj.headers)))
        obj.id = cursor.lastrowid
        # Save the whole request to a json file for later review
        file_name = str(obj.id) + '.json'
        file_path = os.path.join('../logs/requests', file_name)
        with open(file_path, 'w') as f:
            json.dump(json.loads(obj.to_json()), f)
        # Save the threat type
        for threat, location in obj.threats.items():
            cursor.execute("INSERT INTO threats (log_id, threat_type, location) VALUES (?, ?, ?)", (obj.id, threat, location))
        self.conn.commit()

    def __create_entry(self, row) -> dict:
        # Create a dictionary from the row for the DataFrame
        entry = dict(row)
        entry['Link'] = '[Review](http://127.0.0.1:8050/review/'+str(entry['id'])+')'
        return entry

    def read_all(self) -> pd.DataFrame:
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM logs AS l JOIN threats AS t ON l.id = t.log_id")
        results = cursor.fetchall()
        data = [self.__create_entry(row) for row in results]
        return pd.DataFrame(data)

    def __create_single_entry(self, row) -> list:
        return [row['threat_type'], row['location']]

    def read_request(self, id_: int) -> tuple:
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM logs AS l JOIN threats AS t ON l.id = t.log_id WHERE l.id = ?", (id_,))
        results = cursor.fetchall()
        log = dict()
        if len(results) != 0:
            log['timestamp'] = results[0]['timestamp']
            log['origin'] = results[0]['origin']
            log['host'] = results[0]['host']
            log['request'] = results[0]['request']
            log['method'] = results[0]['method']
            log['body'] = results[0]['body']
            log['headers'] = json.loads(results[0]['headers'])
        data = [self.__create_single_entry(row) for row in results]
        return log, data

    def close(self):
        self.conn.close()

db = DBController()
threat_clf = ThreatClassifier()

# define the interesting header fields
header_interesting_fields = interesting_header_list()


def get_header(packet: scapy.Packet) -> dict:
    headers = dict()
    for field in header_interesting_fields:
        f = getattr(packet[HTTPRequest], field)
        if f is not None and f != 'None':
            headers[field] = f.decode()
    return headers


def sniffing_function(packet: scapy.Packet) -> None:
    # Check if the packet is HTTP request
    if packet.haslayer(HTTPRequest):
        req = Request()
        ## To get the origin IP of the request
        if packet.haslayer(IP):
            req.origin = packet[IP].src
        else:
            req.origin = 'localhost'
        ## To get the host (IPv4:Port), request (Path), method and headers of the receiving request
        req.host = urllib.parse.unquote(packet[HTTPRequest].Host.decode())
        req.request = urllib.parse.unquote(packet[HTTPRequest].Path.decode())
        req.method = packet[HTTPRequest].Method.decode()
        req.headers = get_header(packet)
        ## To get the body of the request
        if packet.haslayer(Raw):
            req.body = packet[Raw].load.decode()
        req = threat_clf.classify_request(req)
        db.save(req)
        print(req.to_json())
        print(req.threats)
        print('-----------------------------------')
        
        if len(req.threats) != 0 and 'valid' not in req.threats:
            LOGGER.info(f"Request from {req.origin} to {req.host} is a threat!!!")
    

def main():
    try:
        LOGGER.info("Start sniffing ...")
        LOGGER.info(f"Sniffing on port {args.port} ...")
        if os.name == 'nt':
            # windows
            iface = ifaces.dev_from_index(1)
            LOGGER.info(f"Interface: {iface}")
            sniff(prn=sniffing_function, iface=iface, filter=f'port {args.port}', session = TCPSession)
        elif os.name == 'posix':
            # mac os
            iface = 'lo0'
            LOGGER.info(f"Interface: {iface}")
            sniff(prn=sniffing_function, iface=iface, filter=f'port {args.port}', session = TCPSession)
        else:
            # linux
            iface = 'lo'
            LOGGER.info(f"Interface: {iface}")
            sniff(prn=sniffing_function, iface=iface, filter=f'port {args.port} and inbound', session = TCPSession)
    except KeyboardInterrupt:
        LOGGER.info("Stop sniffing ...")
        db.close()
        exit(0)
    
    
if __name__ == '__main__':
    main()