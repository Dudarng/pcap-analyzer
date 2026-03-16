import pyshark
import ipaddress

ips = set()

captura = pyshark.FileCapture('infected.pcap')

for packet in captura:
    try:    
        ipOrigem = packet.ip.src 
        ipDestino = packet.ip.dst

        ipsO = ipaddress.ip_address(ipOrigem)
        ipsD = ipaddress.ip_address(ipDestino)

        if (not ipsO.is_private) :
            ips.add(ipOrigem)
        if  (not ipsD.is_private) :
            ips.add(ipDestino) 
    except:
        continue 
print(ips)