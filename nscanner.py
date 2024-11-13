#!/usr/bin/env python3
import nmap
import optparse
import socket

def nmapScan(tgtHost, tgtPort):
    #Creates an instance of PortScanner class, which allows you to scan and interact with network hosts and ports.
    nmScan = nmap.PortScanner()

    # Get the ip address 
    tgtHost = socket.gethostbyname(tgtHost)

    nmScan.scan(tgtHost, tgtPort)
    state=nmScan[tgtHost]['tcp'][int(tgtPort)]['state']
    print("[*] " + tgtHost + " tcp/" + tgtPort +" "+state)

def main():
    parser = optparse.OptionParser("usage%prog " + '-H <target_host> -p <target_port>')
    parser.add_option('-H', dest='tgtHost', type='string', help='specify target host')
    parser.add_option('-p', dest='tgtPort', type='string', help='specify target port')

    # Parses command line arguments & returns an object containing argument values
    (options, args)=parser.parse_args()
    
    #Assign value of argument tgtHost to tgtHost
    tgtHost = options.tgtHost

    #Assign value of argument tgtPort to tgtPorts
    tgtPorts= str(options.tgtPort).split(",")
   
    if(tgtHost == None) | (tgtPorts[0] == None):
        print(parser.usage)
        exit(0)
    for tgtPort in tgtPorts:
        nmapScan(tgtHost, tgtPort)

if __name__ == '__main__':
        main()


