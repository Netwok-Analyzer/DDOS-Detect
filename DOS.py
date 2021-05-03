import dpkt
import socket
import argparse

def detectLOIC(pcap):
    for ts,buf in pcap:
        try:
            eth = dpkt.ethernet.Ethernet(buf)
            ip=eth.data
            src=socket.inet_ntoa(ip.src)
            dest=socket.inet_ntoa(ip.dst)
            
            tcp = ip.data
            
            http=dpkt.http.Request(tcp.data)
            if http.method =="GET":
                uri=http.uri.lower()
                if ".zip" in uri and "loic" in uri:
                    print("[!] " + src + " Downloaded LOIC" )
        except:
            pass

if __name__ == "__main__":
    parser=argparse.ArgumentParser(description="Detect D-DOS Attack")
    parser.add_argument("-p" , required=True,dest="pcap", help="Add the pcap file location")
    
    args = parser.parse_args()
    pcap = args.pcap

    with open(pcap,"rb") as file:
        pcapf=dpkt.pcap.Reader(file)
        detectLOIC(pcapf)