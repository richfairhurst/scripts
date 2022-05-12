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
import matplotlib.pyplot as plt

# IPInfo Access Token available via ipinfo.io
ipinfo_access_token = os.getenv("IPINFO_KEY")


def split_url_to_domain_to_ip(u, fallback="Unknown"):
    try:
        x = u.split(":")[1]
        x = x.split("//")
        ip: str = socket.gethostbyname(x[1])
        print(f"{u} Resolved to: {ip}")
        return ip
    except socket.gaierror:
        print("Unable to resolve. Logging as Unknown")
        return fallback


def lookup_geo_location(ip, fallback="Unknown"):
    handler = ipinfo.getHandler(ipinfo_access_token)
    try:
        details = handler.getDetails(ip)
        return details.country_name
    except SyntaxError:
        print(f"GeoIP Address Failed for: {ip}")
        # Adding Logging here for manaul review
        return fallback


def chart_top_10(country_numbers):
    # Determine top 10
    r = sorted(country_numbers.items(), key=lambda x: x[1], reverse=True)
    x = []
    y = []
    for i in range(len(r)):
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
    # data = pd.read_csv("URLHaus-6-11.csv")
    url = "https://urlhaus.abuse.ch/downloads/csv_recent/"
    data = pd.read_csv(url, skiprows=8)
    online = data[data['url_status'] == 'online'].reset_index()
    country_count = {}
    if args.s:
        try:
            f = open("urls_and_country_mapping.txt", "w+")
            print("Extracting URL, determining IP and writing to file")
        except IOError:
            print('Unable to open file, no longer writing to file')
    for i in range(len(online)):
        malware_urls = data['url'][i]
        malware_domain = split_url_to_domain_to_ip(malware_urls)
        if args.s:
            try:
                f.write(f"{malware_urls} : {malware_domain}\n")
            except IOError:
                print('Unable to open file, no longer writing to file')
        if malware_domain != 'Unknown':  # IP Address lookup failed, no point trying to geo-locate
            geo_country = lookup_geo_location(malware_domain)
            country_count[geo_country] = country_count.get(geo_country, 0) + 1
    if args.s:
        f.close()
        f = open("country_count.txt", "w+")
    print("********** Country Count **********")
    for key, value in country_count.items():
        print(f"{key} : {value}")
        if args.s:
            f.write(f"{key} : {value}\n")
            f.close()
    chart_top_10(country_count)
