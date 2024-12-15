import scapy.all as scapy
import urllib.parse
import Logger
import os
from scapy.all import sniff, Raw, ifaces
from scapy.layers.http import HTTPRequest, HTTP
from scapy.layers.inet import IP, TCP
from scapy.sessions import TCPSession
from Request.Request import Request, interesting_header_list
from DBController import DBController
from Classifier import ThreatClassifier
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
