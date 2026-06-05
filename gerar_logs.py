import json
import time
from datetime import datetime, timedelta

LOG_FILE = "auth_simulator.log"
FORMATO_TIMESTAMP = "%Y-%m-%d %H:%M:%S"

def injetar_log(dados):
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(dados) + "\n")
    time.sleep(2)  # Intervalo para você conseguir acompanhar no terminal

print("[+] Injetor de logs do VaultSentry iniciado.")
print("[+] Gerando cenários de teste... Olhe o terminal do monitor!")

agora = datetime.now()

# -----------------------------------------------------------------
# CENÁRIO 1: Acesso legítimo do Gustavo em Osasco
# -----------------------------------------------------------------
log_valido = {
    "usuario": "gustavo.izidio",
    "ip": "189.122.34.10",
    "localizacao": "Osasco-BR",
    "user_agent": "Chrome-Trusted",
    "token_sessao": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.sentry_token_101",
    "timestamp": agora.strftime(FORMATO_TIMESTAMP)
}
print("\n-> Injetando Evento 1: Autenticação bem-sucedida de gustavo.izidio (Osasco)")
injetar_log(log_valido)


# -----------------------------------------------------------------
# CENÁRIO 2: Navegação contínua legítima (Mesmo IP, Mesmo User-Agent)
# -----------------------------------------------------------------
agora_mais_dois_segundos = agora + timedelta(seconds=2)
log_navegacao = log_valido.copy()
log_navegacao["timestamp"] = agora_mais_dois_segundos.strftime(FORMATO_TIMESTAMP)

print("-> Injetando Evento 2: Requisição normal de API (Mantendo a sessão ativa)")
injetar_log(log_navegacao)


# -----------------------------------------------------------------
# CENÁRIO 3: Ataque de Impossible Travel (Sessão usada na Rússia 5s depois)
# -----------------------------------------------------------------
agora_mais_cinco_segundos = agora + timedelta(seconds=5)
log_ataque = {
    "usuario": "gustavo.izidio",
    "ip": "95.213.255.1",
    "localizacao": "Moscou-RU",
    "user_agent": "Chrome-Trusted", # Clonou o UA para tentar burlar
    "token_sessao": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.sentry_token_101", # Token roubado
    "timestamp": agora_mais_cinco_segundos.strftime(FORMATO_TIMESTAMP)
}
print("-> 🔥 ATENÇÃO: Injetando tentativa de Session Hijacking originada na Rússia!")
injetar_log(log_ataque)

print("\n[+] Cenários injetados no arquivo auth_simulator.log.")
