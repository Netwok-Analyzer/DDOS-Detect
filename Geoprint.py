import geoip2.database #used to handle maxmind database
import argparse
import socket
import dpkt           #read the packets


def ret_geo_ip(ip):  #for returning the geo location 

    try:
        with geoip2.database.Reader("GeoLite2-City.mmdb") as geofile:
            rec= geofile.city(ip)
            city=rec.city.name
            country=rec.country.name
            return f"{city}, {country}" if city else country
    
    except Exception as e:
        print(f'{"":>3}[-] Exception: {e.__class__.__name__}')
        return 'Unregistered'



class print_pcap:   
    def __init__(self,pcap_file):
        self.pcap_file = pcap_file 

    def printit(self):
        try:
            for ts,buf in pcap:
                eth = dpkt.ethernet.Ethernet(buf)
                ip = eth.data
                src=socket.inet_ntoa(ip.src)
                dest=socket.inet_ntoa(ip.dest)
                print(f"[+] src: {ret_geo_ip(src)} --> Dest: {ret_geo_ip(dest)}")
        except Exception as e:
            print(f'{"":>3}[-] Exception: {e.__class__.__name__}')
            pass

if __name__ == "__main__":
    parser=argparse.ArgumentParser(description="Print the GeoLocation of the IP adress ")
    parser.add_argument("-p" ,required=True, dest="pcap", help="Add the pacap file location")
    
    args= parser.parse_args()
    pcap = args.pcap

    with open(pcap,"rb") as file:
        pcapf=dpkt.pcap.Reader(file)
        s1=print_pcap(pcapf)
        s1.printit()

