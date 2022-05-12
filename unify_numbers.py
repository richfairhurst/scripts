#!/usr/bin/python


import urllib2
import re
import sys
import threading
from bs4 import BeautifulSoup
from netaddr import *

LOCK = threading.Lock()


def usage():
    print("unify_numbers.py")
    print("Takes a CIDR range as an arguement and scans for Siemens/Unify phones and prints out number")
    print("Usage: ./unify_numbers.py [CIDR]")
    print("Example: ./unify_numbers.py 102.0.2.0/23")


def get_number(ip):
    try:
        soup = BeautifulSoup(urllib2.urlopen("https://" + ip + "/main_banner.cmd?lan=en", timeout=2))
        LOCK.acquire()
        print("[+]", ip, "is an :", soup.findAll('td')[3].string, "and has phone number ",
              re.findall(r"[\w']+", str(soup('td', {'class': 'text_left'})[0]))[3])
        LOCK.release()
    except:
        pass


def main():
    if len(sys.argv) < 2:
        usage()
        sys.exit()
    else:
        ip = sys.argv[1]
        threads = []
        for ip in IPNetwork(ip).iter_hosts():
            addr = str(ip)
            t = threading.Thread(target=get_number, args=(addr,))
            threads.append(t)

        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        print("Done!")


if __name__ == '__main__':
    main()
