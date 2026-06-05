import time
import os
import json
import hashlib
from datetime import datetime

# ===============================
# CONFIG
# ===============================
LOG_FILE = "auth_simulator.log"
SESSION_FILE = "sessions.json"
TOTP_FILE = "totp_secrets.json"
FORMATO_TIMESTAMP = "%Y-%m-%d %H:%M:%S"

WHITELIST_IPS = {"127.0.0.1"}
WHITELIST_UA = {"Trusted-Agent"}

RATE_LIMIT = 30  # segundos
ULTIMO_ALERTA = {}

# ===============================
# UTIL
# ===============================

def carregar_json(file):
    if os.path.exists(file):
        with open(file, "r") as f:
            return json.load(f)
    return {}

def salvar_json(file, data):
    with open(file, "w") as f:
        json.dump(data, f, indent=2)

# ===============================
# BASE DE DADOS
# ===============================
SESSOES = carregar_json(SESSION_FILE)
TOTP_SECRETS = carregar_json(TOTP_FILE)

# ===============================
# TOTP (persistente)
# ===============================

def gerar_secret(usuario):
    if usuario not in TOTP_SECRETS:
        segredo = hashlib.sha1(usuario.encode()).hexdigest()
        TOTP_SECRETS[usuario] = segredo
        salvar_json(TOTP_FILE, TOTP_SECRETS)
    return TOTP_SECRETS[usuario]

def gerar_totp(usuario):
    segredo = gerar_secret(usuario)
    intervalo = int(time.time() // 30)
    base = f"{segredo}{intervalo}"
    return hashlib.sha1(base.encode()).hexdigest()[:6]

# ===============================
# ALERTA COM RATE LIMIT
# ===============================

def pode_alertar(usuario):
    agora = time.time()
    ultimo = ULTIMO_ALERTA.get(usuario, 0)

    if agora - ultimo > RATE_LIMIT:
        ULTIMO_ALERTA[usuario] = agora
        return True
    return False

def alerta(tipo, usuario, motivo):
    if not pode_alertar(usuario):
        return

    print("\n" + "="*50)
    print(f"[🚨 ALERTA] {tipo}")
    print(f"Usuário: {usuario}")
    print(f"Motivo: {motivo}")
    print("="*50 + "\n")

# ===============================
# REGRAS
# ===============================

def viagem_impossivel(local1, local2, delta):
    return local1 != local2 and delta < 30

def ip_anomalo(ip1, ip2):
    return ip1 != ip2

# ===============================
# ANALISADOR
# ===============================

def analisar_log(log):
    try:
        usuario = log.get("usuario")
        ip = log.get("ip")
        local = log.get("localizacao")
        ua = log.get("user_agent")
        token = log.get("token_sessao")
        tempo = log.get("timestamp")

        if not all([usuario, ip, local, ua, tempo]):
            return

        agora = datetime.strptime(tempo, FORMATO_TIMESTAMP)

        token_preview = token[:8] + "..." if token else "N/A"

        print(f"[INFO] {tempo} | {usuario} | {token_preview}")

        # ✅ WHITELIST
        if ip in WHITELIST_IPS and ua in WHITELIST_UA:
            print("[SAFE] Ignorado por whitelist")
            return

        if usuario in SESSOES:
            sessao = SESSOES[usuario]

            anterior = datetime.strptime(sessao["timestamp"], FORMATO_TIMESTAMP)
            delta = (agora - anterior).total_seconds()

            # 🚨 Session Hijacking
            if sessao["user_agent"] != ua:
                alerta("Session Hijacking", usuario, "User-Agent mudou")
                return

            # 🌍 Impossible Travel
            if viagem_impossivel(sessao["localizacao"], local, delta):
                alerta("Impossible Travel", usuario, f"{delta:.1f}s")

                codigo = gerar_totp(usuario)
                print(f"[MFA] Código TOTP: {codigo}")
                return

            # 🌐 Mudança de IP
            if ip_anomalo(sessao["ip"], ip):
                alerta("IP Anômalo", usuario, "IP mudou durante sessão")
                return

        # ✅ Atualiza sessão
        SESSOES[usuario] = {
            "ip": ip,
            "localizacao": local,
            "user_agent": ua,
            "timestamp": tempo
        }

        salvar_json(SESSION_FILE, SESSOES)

    except Exception as e:
        print(f"[ERRO ANALISE] {e}")

# ===============================
# MONITOR CONTÍNUO (tail -f)
# ===============================

def ler_linhas(arquivo):
    arquivo.seek(0, os.SEEK_END)

    while True:
        linha = arquivo.readline()

        if not linha:
            time.sleep(0.5)
            continue

        yield linha

# ===============================
# START
# ===============================

def iniciar():
    print("="*60)
    print(" VAULTSENTRY - MONITOR DE SESSÕES ")
    print("="*60)

    if not os.path.exists(LOG_FILE):
        open(LOG_FILE, "w").close()

    with open(LOG_FILE, "r") as f:
        for linha in ler_linhas(f):
            try:
                dados = json.loads(linha.strip())
                analisar_log(dados)
            except json.JSONDecodeError:
                continue
            except Exception as e:
                print(f"[ERRO] {e}")

# ===============================
# RUN
# ===============================
if __name__ == "__main__":
    iniciar()