####################################################
# Description: loads latest URLHaus recent CSV file,
# translates to IP and GeoIP lookup to derive top
# 10 countries
####################################################
import os
import argparse
import socket
import ipinfo
import pandas as pd
#from urllib import URLopener
from urllib.parse import urlsplit

import matplotlib.pyplot as plt

# IPInfo Access Token available via ipinfo.io
ipinfo_access_token = os.getenv("EMAIL")


def split_url_to_domain_to_ip(u, fallback="Unknown"):
    try:
        ip = socket.gethostbyname("{0.netloc}".format(urlsplit(u)))
        #print (ip)
        return ip
    except BaseException:
        print(
            f"URL to Domain to IP Address failed for {u}. Attemping to resolve...")
        try:
            x = u.split(":")[1]
            x = x.split("//")
            ip = socket.gethostbyname(x[1])
            print(f"Resolved to: {ip}")
            return ip
        except BaseException:
            print(" Unable to resolve. Logging as Unknown")
            return fallback
    return fallback


def lookup_geo_location(ip, fallback="Unknown"):
    handler = ipinfo.getHandler(ipinfo_access_token)
    try:
        details = handler.getDetails(ip)
        return details.country_name
    except BaseException:
        print(f"GeoIP Address Failed for: {ip}")
        # Adding Logging here for manaul review
        return fallback


def chart_top_10(dict):
    # Determine top 10
    r = sorted(dict.items(), key=lambda x: x[1], reverse=True)
    x = []
    y = []
    for i in range(10):
        x.append(r[i][0])
        y.append(r[i][1])

    # Plot and Show Chart
    plt.bar(x, y, label='Bar Chart', align='center', width=0.3)
    plt.xlabel('Country')
    plt.ylabel('Malware Instances')
    plt.title('Top 10 Countires with online Malware in URLHaus Recent Records')
    plt.xticks(rotation=90)
    plt.gcf().subplots_adjust(bottom=0.30)
    if args.s:
        print('Saving chart')
        plt.savefig('top_10.png')
    plt.show()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-s", "--s", action='store_true',
                        help="save domain and country mapping to urls.txt, and chart to top_10.png")
    args = parser.parse_args()

    # Could grab direct:
    #testfile = urllib.URLopener()
    #testfile.retrieve("https://urlhaus.abuse.ch/downloads/csv_recent/", "URLHaus.gz")
    # then need to skip top 8 lines, otherwise just open locally:
    #
    data = pd.read_csv("URLHaus-6-11.csv")
    online = data[data['url_status'] == 'online']
    country_count = {}
    if args.s:
        f = open("urls_and_country_mapping.txt", "w+")
    print("Extracting URL, determining IP and writting to file")
    for i in range(len(online)):
        u = data['url'][i]
        # print (u)
        d = split_url_to_domain_to_ip(u)
        if args.s:
            f.write(f"{u} : {d}\n")
        if d != 'Unknown':  # IP Address lookup failed, no point trying to geo-locate
            g = lookup_geo_location(d)
            # print(f"{i} {u} {g}")
            country_count[g] = country_count.get(g, 0) + 1
    if args.s:
        f.close()
        f = open("country_count.txt", "w+")
    print("********** Country Count **********")
    for key, value in country_count.items():
        print(f"{key} : {value}")
        if args.s:
            f.write(f"{key} : {value}\n")
    chart_top_10(country_count)
    f.close()
