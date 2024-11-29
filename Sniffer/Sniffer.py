import scapy.all as scapy
import urllib.parse
import Logger
import os
from scapy.all import sniff, Raw, ifaces, send
from scapy.layers.http import HTTPRequest, HTTP
from scapy.layers.inet import IP, TCP
from scapy.sessions import IPSession, TCPSession
from Request import Request
from DBController import DBController
from Classifier import ThreatClassifier
from argparse import ArgumentParser

LOGGER = Logger.init_logging('sniffing', 'WAF')

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
header_interesting_fields = ['Http_Version',
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


def get_header(packet: scapy.Packet) -> dict:
    headers = dict()
    for field in header_interesting_fields:
        f = getattr(packet[HTTPRequest], field)
        if f is not None and f != 'None':
            headers[field] = f.decode()
    return headers


def force_close_connection(src_ip, src_port, dst_ip, dst_port):
    # Create a TCP FIN packet
    fin_packet = IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags='FA')
    # Send the packet
    print(f"Force close connection from {src_ip}:{src_port} to {dst_ip}:{dst_port}")
    send(fin_packet)


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
