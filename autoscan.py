#!/usr/bin/env python
#coding=utf-8
#author="JeeWin'

import nmap
import urllib2
import sys
from multiprocessing import Pool


def getUrl(url):
    print url + '@',
    try:
        response = urllib2.urlopen(url,timeout=10)
        #r = requests.get(url, verify=False)
        print response.getcode()
    except urllib2.URLError,e:
        print e.reason
    except urllib2.HTTPError,e:
        print e.code
    except Exception,e:
        print e

if __name__ == "__main__":
    target = sys.argv[1]
    ports = '80,8080,7001'

    nm = nmap.PortScanner()
    nm.scan(hosts = target, arguments = '-sS -T4 -Pn -p ' + ports)

    lport = ports.split(',')
    lport.sort()

    urls=[]

    for port in lport:
        for host in nm.all_hosts():
            if 'open' == nm[host]['tcp'][int(port)]['state']:
                if port=='443':
                    url = 'https://' + host + ':' + port
                else:
                    url = 'http://' + host + ':' + port
                urls.append(url)

    pool = Pool(20)
    pool.map(getUrl, urls)
