import geoip2.database #used to handle maxmind database
import argparse
import socket
import dpkt           #read the packets
# import google_Earth as gogo

def ret_geo_ip(ip):  #for returning the geo location 

    try:
        with geoip2.database.Reader("GeoLite2-City.mmdb") as geofile:
            rec= geofile.city(ip)
            city=rec.city.name
            country=rec.country.name
            return f"{city}, {country}" if city else country
    
    except Exception as e:
        print("[-] "+str(e))
        return 'Unregistered'



# class print_pcap:   
#     def __init__(self,pcap_file):
#         self.pcap_file = pcap_file 

#     def printit(self):
#         for ts,buf in pcap:
#             try:
#                 eth = dpkt.ethernet.Ethernet(buf)
#                 ip = eth.data #get the ip data
#                 src=socket.inet_ntoa(ip.src)
#                 dest=socket.inet_ntoa(ip.dst)
#                 print(f"[+] src: {ret_geo_ip(src)} --> Dest: {ret_geo_ip(dest)}")
#             except Exception as e:
#                 print(e)
                # pass

def printit(pcap):
    for ts,buf in pcap: #ts= timestamp and buf= length  
        try:
            eth = dpkt.ethernet.Ethernet(buf)
            # print(eth) #repr()
            ip = eth.data #get the ip data
            src=socket.inet_ntoa(ip.src) #converts to dooted quad string notation
            dest=socket.inet_ntoa(ip.dst)
            print(f"[+] src: {src} --> Dest: {dest}")
            print(f"[+] src: {ret_geo_ip(src)} --> Dest: {ret_geo_ip(dest)}")
        except Exception as e:
            print(e)

if __name__ == "__main__":
    parser=argparse.ArgumentParser(description="Print the GeoLocation of the IP adress ")
    parser.add_argument("-p" ,required=True, dest="pcap", help="Add the pacap file location")
    # parser.add_argument("-g" ,required=False, help="Reperesent on Google Earth")
    args= parser.parse_args()
    pcap = args.pcap

    with open(pcap,"rb") as file:
        pcapf=dpkt.pcap.Reader(file)
        printit(pcapf)
        # kmlheader = '<?xml version="1.0" encoding="UTF-8"?>' \
        #             '\n<kml xmlns="http://www.opengis.net/kml/2.2">' \
        #             '\n<Document>\n'
        # kmlfooter = '</Document>\n</kml>\n'
        # kmldoc = kmlheader + gogo.plot_IPs(pcapf) + kmlfooter    
        # print(kmldoc)
    
