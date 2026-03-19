import pyshark
import ipaddress
from enricher import getVirusTotal, getAbuseIPDB
import time

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
print(f"Leitura do arquivo concluída")
print(f"Total de IPs: {len(ips)}")
print(f"Iniciando analise de IPs")

for ip in ips:
    vt = getVirusTotal(ip)
    ipdb = getAbuseIPDB(ip)
    
    if vt.get("erro") or ipdb.get("erro"):
        print(f"[-] Problema ao analisar {ip}: {vt.get('erro')} | {ipdb.get('erro')}")
        time.sleep(16)
        continue
    
    maliciosos_vt = vt['malicioso']
    score_abuse = ipdb['score_abuso']
    
    if maliciosos_vt > 0 or score_abuse > 0:
        print(f"[ALERTA] IP: {ip}")
        print(f"Organização: {vt['dono']} (País: {ipdb['pais']})")
        if maliciosos_vt > 0 :
            print(f"{maliciosos_vt} motores classificaram como malicioso.")
        print(f"Score de {score_abuse}% de confiança de abuso. ({ipdb['total_reportes']} denúncias recentes)")
        print(f"Tipo de Ataque: {ipdb["motivos"]}\n")
    time.sleep(16)
    
print("Analise concluida")