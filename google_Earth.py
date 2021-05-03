import dpkt
import socket
import geoip2.database
import argparse
import webbrowser


def ret_KML(ip):
    with geoip2.database.Reader("GeoLite2-City.mmdb") as gi:
        rec = gi.city(ip)

        try:
            latitude = rec.location.latitude
            longitude = rec.location.longitude
            kml = (
                      f'<Placemark>\n'
                      f'<name>{ip}</name>\n'
                      f'<Point>\n'
                      f'<coordinates>{latitude:f},{longitude:f}</coordinates>\n'
                      f'</Point>\n'
                      f'</Placemark>\n'
                  )
            return kml

        except Exception as e:
            print(e)
            return ''


def plot_IPs(pcap):
    kml_pts = ''

    for ts, buf in pcap:
        try:
            eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data
            src = socket.inet_ntoa(ip.src)
            dst = socket.inet_ntoa(ip.dst)

            src_kml = ret_KML(src)
            dst_kml = ret_KML(dst)

            kml_pts = kml_pts + src_kml + dst_kml

        except Exception as e:
            print(e)
            pass

    return kml_pts

#send_kml

if __name__ == "__main__":
    parser=argparse.ArgumentParser(description="Print the GeoLocation of the IP adress ")
    parser.add_argument("-p" ,required=True, dest="pcap", help="Add the pacap file location")
    
    args= parser.parse_args()
    pcap = args.pcap

    with open(pcap,"rb") as file:
        pcapf=dpkt.pcap.Reader(file)
        kmlheader = '<?xml version="1.0" encoding="UTF-8"?>' \
                    '\n<kml xmlns="http://www.opengis.net/kml/2.2">' \
                    '\n<Document>\n'
        kmlfooter = '</Document>\n</kml>\n'
        kmldoc = kmlheader + plot_IPs(pcapf) + kmlfooter

        with open("Google_mapped.kml","a+") as files:
            files.writelines(kmldoc)
    
    webbrowser.open("https://earth.google.com/web/")