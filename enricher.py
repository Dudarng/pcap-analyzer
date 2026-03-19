import os
import requests
from dotenv import load_dotenv

load_dotenv()
API_KEY_VIRUSTOTAL = os.getenv("API_KEY_VIRUSTOTAL") 
API_KEY_IPDB = os.getenv("API_KEY_IPDB")

def getVirusTotal(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    cabecalhos = {"x-apikey": API_KEY_VIRUSTOTAL}

    print(f"[*] Verificação para o IP: {ip}...")

    
    try:
        resposta = requests.get(url, headers=cabecalhos)
    except Exception as erro_rede:
        return f"[-] Erro de conexão ao tentar alcançar o VirusTotal para o IP {ip}: {erro_rede}"

    
    if resposta.status_code == 200:
        dados = resposta.json()
        as_owner = dados['data']['attributes'].get('as_owner', 'Desconhecido')
        stats = dados['data']['attributes']['last_analysis_stats']
        
        return {
            "dono": as_owner,
            "malicioso": stats['malicious'],
            "inofensivo": stats['harmless'],
            "indetectavel": stats['undetected'],
            "erro": None
        }
        
    elif resposta.status_code == 401:
        return f"[-] Erro 401: Acesso Negado no IP {ip}. Chave incorreta."
    elif resposta.status_code == 429:
        return f"[-] Erro 429: Limite de requisições excedido na API."
    else:
        return f"[-] Falha ao verificar IP {ip}. Código: {resposta.status_code}"

def getAbuseIPDB(ip):
    url = "https://api.abuseipdb.com/api/v2/check"
    cabecalhos = {
        'Accept': 'application/json',
        'Key': API_KEY_IPDB
    }
    parametros = {
        'ipAddress': ip,
        'maxAgeInDays': '90',
        'verbose': '1'
    }
    attackType = {
        1: "DNS Compromise",
        2: "DNS Poisoning",
        3: "Fraude (Fraud Orders)",
        4: "Ataque DDoS",
        5: "Força Bruta em FTP",
        6: "Ping of Death",
        7: "Phishing",
        8: "Fraude em VoIP",
        9: "Open Proxy",
        10: "Spam em Fóruns/Web",
        11: "Spam de Email",
        12: "Spam em Blogs",
        13: "IP de VPN (Comportamento Suspeito)",
        14: "Varredura de Portas (Port Scan)",
        15: "Hacking / Tentativa de Invasão",
        16: "Injeção de SQL (SQLi)",
        17: "Falsificação de Origem (Spoofing)",
        18: "Ataque de Força Bruta (Geral)",
        19: "Bot Malicioso (Bad Web Bot)",
        20: "Host Comprometido/Infectado",
        21: "Ataque a Aplicação Web",
        22: "Força Bruta em SSH",
        23: "Ataque a Dispositivos IoT"
    }
    try:
       
        resposta = requests.get(url, headers=cabecalhos, params=parametros)
    except Exception as erro_rede:
        return {"erro": f"Falha de rede ao contatar AbuseIPDB: {erro_rede}"}

    if resposta.status_code == 200:
        dados = resposta.json()
        
        attackSearch = set()
        reports = dados['data'].get('reports', [])
        
        for rep in reports:
            for cat_id in rep.get('categories', []):
                nameCat = attackType.get(cat_id, f"Outros ({cat_id})")
                attackSearch.add(nameCat)
        searchText = ", ".join(attackSearch) if attackSearch else "Não especificada"
        
      
        return {
            "score_abuso": dados['data']['abuseConfidenceScore'],
            "total_reportes": dados['data']['totalReports'],
            "pais": dados['data']['countryCode'],
            "motivos": searchText, 
            "erro": None
        }
    else:
        return {"erro": f"Erro na API do AbuseIPDB. Código: {resposta.status_code}"}
    

if __name__ == "__main__":
    resultado = getVirusTotal("8.8.8.8")
    print(resultado)