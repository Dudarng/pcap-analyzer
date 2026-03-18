import os
import requests
from dotenv import load_dotenv

# 1. Abre o cofre e carrega a chave secreta
load_dotenv()
# O nome dentro do getenv() tem que ser exatamente o que você escreveu no arquivo .env
API_KEY_VIRUSTOTAL = os.getenv("API_KEY_VIRUSTOTAL") 

# 2. A sua lógica de montagem
ip_teste = "8.8.8.8"
url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_teste}"
cabecalhos = {"x-apikey": API_KEY_VIRUSTOTAL}

print(f"[*] Verificação para o IP: {ip_teste}...")

# 3. O "Botão de Enviar": Fazendo a requisição GET
resposta = requests.get(url, headers=cabecalhos)

# 4. Verificando a resposta do servidor
print(f"Status Code: {resposta.status_code}")

if resposta.status_code == 200:
    print("[+] Conexão aceita:")
    # O método .json() pega a resposta bruta e transforma numa estrutura legível para o Python
    dados_estruturados = resposta.json()
    print(dados_estruturados)
elif resposta.status_code == 401:
    print("[-] Erro 401: Acesso Negado. Sua chave da API está incorreta ou não foi lida do .env.")
else:
    print(f"[-] Erro inesperado. Código: {resposta.status_code}")