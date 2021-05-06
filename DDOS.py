import dpkt
import socket
import argparse
THRES=10000

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

def findhive(pcap):
    for ts,buf in pcap:
        try:
            eth=dpkt.ethernet.Ethernet(buf)
            ip=eth.data
            src=socket.inet_ntoa(ip.src)
            dest=socket.inet_ntoa(ip.dst)
        
            tcp=ip.data
            
            dport=tcp.dport
            sport=tcp.sport

            if dport==6667:
                if "!lazor" in tcp.data.lower().decode('utf-8'):
                    print("[!]  DDoS Hivemind issued by the " + src)
                    print("Target CMD : " + tcp.data.decode("utf-8"))
                    
            
            if sport==6667:
                if "!lazor" in tcp.data.lower():
                    print("[!]  DDoS Hivemind issued by the " + src)
                    print("Target CMD : " + tcp.data)

        except Exception as e:
            pass

def findattack(pcap):
    pktcount={}
    for ts,buf in pcap:
        try:
            eth=dpkt.ethernet.Ethernet(buf)
            ip=eth.data
            src=socket.inet_ntoa(ip.src)
            dest=socket.inet_ntoa(ip.dst)
        
            tcp=ip.data
            
            dport=tcp.dport

            if dport==80:
                stream= src + ":" + dest
                if stream in pktcount:
                    pktcount[stream]=pktcount[stream]+1
                else:
                    pktcount[stream]=1
            
        except:
            pass

    for stream in pktcount:
        pktsent=pktcount[stream]
        if pktsent > THRES:
            srce=stream.split(":")[0]
            dst=stream.split(":")[1]
            print("[+] " + srce +" attacked " + dst +" with " + str(pktsent) + " packets")

def DOSmain(pcap):
    # parser=argparse.ArgumentParser(description="Detect D-DOS Attack")
    # parser.add_argument("-p" , required=True,dest="pcap", help="Add the pcap file location")
    
    # args = parser.parse_args()
    # pcap = args.pcap

    with open(pcap,"rb") as file:
        pcapf=dpkt.pcap.Reader(file)
        detectLOIC(pcapf)
    
    with open(pcap,"rb") as file:
        pcapf=dpkt.pcap.Reader(file)
        findhive(pcapf)

    with open(pcap,"rb") as file:
        pcapf=dpkt.pcap.Reader(file)
        findattack(pcapf)