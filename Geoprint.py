import geoip2.database #used to handle maxmind database
import argparse
import socket
import dpkt           #read the packets
import google_Earth as gogo
import DDOS

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
    parser.add_argument("-l" ,required=True, dest="pcap", help="Add the pacap file location")
    parser.add_argument("-g" ,required=False, dest="gearth" ,help="Want a Kml file to see on google earth? Yes/No")
    parser.add_argument("-d" ,required=False, dest="Dos" ,help="Check for the DOS attack")
    parser.add_argument("-p" ,required=False, dest="print" ,help="print the geolocation of the IP adresses")
    args= parser.parse_args()
    pcap = args.pcap
    gearth=args.gearth
    dos=args.Dos
    prnt=args.print
    


    with open(pcap,"rb") as file:
        pcapf=dpkt.pcap.Reader(file)
        printit(pcapf)

    if gearth=="Yes":
        with open(pcap,"rb") as file:
            pcapf=dpkt.pcap.Reader(file)
            kmlheader = '<?xml version="1.0" encoding="UTF-8"?>' \
                        '\n<kml xmlns="http://www.opengis.net/kml/2.2">' \
                        '\n<Document>\n'
            kmlfooter = '</Document>\n</kml>\n'
            kmldoc = kmlheader + gogo.plot_IPs(pcapf) + kmlfooter 
            with open("Google_mapped.kml","a+") as files:
                files.writelines(kmldoc)
   
    with open(pcap,"rb") as file:
        pcapf=dpkt.pcap.Reader(file)
        DDOS.DOSmain(pcap)
    
