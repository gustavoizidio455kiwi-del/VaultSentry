# 🛠️ VaultSentry - Token & Session Leak Monitor

O **VaultSentry** é uma ferramenta de monitoramento contínuo e resposta a incidentes (Micro-SOC) desenvolvida em Python, focada na detecção de roubo de sessões (*Session Hijacking*) e desvios de identidade corporativa em ecossistemas de *Identity and Access Management (IAM)*.

O sistema simula a ingestão contínua de logs de autenticação corporativos (provenientes de gateways de VPN, firewalls ou IDPs como Okta/Azure AD) e aplica regras de correlação de eventos em tempo real para mitigar ameaças à identidade.

## ⚙️ Funcionalidades e Regras de Correlação

- **🌍 Detecção de Viagem Impossível (Impossible Travel):** Identifica se uma mesma credencial realizou requisições a partir de geolocalizações distintas em um intervalo de tempo fisicamente impossível (ex: login em Osasco-BR e, 5 segundos depois, requisição vinda de Moscou-RU).
- **🕵️‍♂️ Validação de Fingerprint (User-Agent):** Identifica se o navegador ou sistema operacional que está consumindo o token de sessão foi alterado abruptamente no meio de uma atividade legítima (Mapeado na Tática de Persistência do MITRE ATT&CK - T1539).
- **🌐 Monitoramento de IP Anômalo:** Detecta mudanças de endereço de rede durante a mesma sessão ativa, permitindo auditoria de tráfego.
- **🔐 Resposta Ativa via MFA Emergencial:** Ao detectar anomalias críticas (como o *Impossible Travel*), o sistema gera um segredo criptográfico e um token dinâmico **TOTP (MFA)** persistente em tempo real, isolando o atacante e exigindo reautenticação do usuário real.
- **💾 Persistência de Estado:** Mantém o estado das sessões corporativas ativo e seguro através de arquivos JSON, simulando um banco de dados leve de alta disponibilidade.

## 🚀 Como Executar o Laboratório

### 1. Iniciar o Core de Correlação (Monitor Engine)
Execute o monitor para iniciar a escuta ativa do arquivo de logs simulado (com comportamento similar ao `tail -f` do Linux):
```bash
python monitor.py


2. Injetar os Cenários de Ataque
Em outro terminal, execute o script injetor para simular o fluxo de navegação do usuário legítimo e a tentativa de infiltração a partir do IP anômalo:

Bash
python gerar_logs.py




🛠️ Tecnologias Utilizadas
Python 3 (Lógica do motor de correlação, tratamento de timestamps e automação).

Criptografia / Hashing (SHA-1) (Cálculo dinâmico e validação de segredos TOTP/MFA).

JSON (Estruturação de logs e persistência de dados em disco).
---

### 💾 Salvando o arquivo:
1. Vá até o final da página.
2. No botão verde, clique em **`Commit changes...`** (Confirmar alterações)
3. Na caixinha que abrir, pode clicar em **`Commit changes`** de novo para confirmar.

Feito isso, o seu repositório vai ganhar uma cara super profissional na página inicial! Me avisa quando terminar para fazermos o último passo, que é subir os arquivos de código (`monitor.py` e `gerar_logs.py`). 🦾🔥
