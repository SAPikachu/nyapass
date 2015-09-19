#!/usr/bin/env python

# Script originally written by Young Ng (fivesheep @ GitHub)
# Modified by SAPikachu

from __future__ import print_function
import re
import urllib2
import sys
import math

def process_v4(data):
    cnregex=re.compile(r'apnic\|cn\|ipv4\|[0-9\.]+\|[0-9]+\|[0-9]+\|a.*',re.IGNORECASE)
    cndata=cnregex.findall(data)
    
    results=[]

    for item in cndata:
        unit_items=item.split('|')
        starting_ip=unit_items[3]
        num_ip=int(unit_items[4])
        
        imask=0xffffffff^(num_ip-1)
        #convert to string
        imask=hex(imask)[2:]
        mask=[0]*4
        mask[0]=imask[0:2]
        mask[1]=imask[2:4]
        mask[2]=imask[4:6]
        mask[3]=imask[6:8]
        
        #convert str to int
        mask=[ int(i,16 ) for i in mask]
        mask="%d.%d.%d.%d"%tuple(mask)
        
        #mask in *nix format
        mask2=32-int(math.log(num_ip,2))
        
        results.append((starting_ip,mask,mask2))
         
    return results

def process_v6(data):
    cnregex=re.compile(r'apnic\|cn\|ipv6\|[0-9a-f:]+\|[0-9]+\|[0-9]+\|a.*',re.IGNORECASE)
    cndata=cnregex.findall(data)
    
    results=[]

    for item in cndata:
        unit_items=item.split('|')
        starting_ip=unit_items[3]
        prefix_size=int(unit_items[4])
        
        results.append((starting_ip,prefix_size,prefix_size))
         
    return results

def fetch_ip_data():
    #fetch data from apnic
    print("Fetching data from apnic.net, it might take a few minutes, please wait...", file=sys.stderr)
    url=r'http://ftp.apnic.net/apnic/stats/apnic/delegated-apnic-latest'
    data=urllib2.urlopen(url).read()
    return process_v4(data) + process_v6(data)

def build_route_script(format="{ip}/{mask}"):
    ips = fetch_ip_data()
    with open("chnetworks.txt", "w") as f:
        for ip, _, mask in ips:
            f.write(format.format(ip=ip, mask=mask) + "\n")

if __name__ == "__main__":
    build_route_script(*sys.argv[1:])
