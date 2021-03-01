import geoip2.database #used to handle maxmind database
gi=geoip2.database.Reader("GeoLite2-City.mmdb")
print(gi.city('55.192.208.240').country.name)