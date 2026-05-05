# 👾 PS.Chat Admin

[![Version](https://img.shields.io/badge/version-2.2.9-blue.svg)](https://github.com/PSecurity/ps.chat-admin/releases)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.9%2B-yellow.svg)](https://python.org)
[![Termux](https://img.shields.io/badge/Termux-Compatible-red.svg)](https://termux.com)

**Servidor de chat privado, offline e com administração centralizada** – ideal para redes locais, eventos, equipes ou comunicação interna sem depender da internet.

> ⚡ **Novo na v2.2.9:** E2EE com chave de sala, DM criptografada, verificação de identidade, banimento por dispositivo, painel responsivo, moderação completa e modo daemon.

---

## ✨ Funcionalidades

### 🔒 Segurança
- **E2EE ponta a ponta** – chave de sala (X25519 + AES‑GCM + Ed25519) + mensagens diretas criptografadas
- **Verificação de identidade** – `/verify` com desafio de assinatura digital
- **Banimento permanente** – por chave pública + ID do dispositivo
- **Rate limiting** – 5 tentativas de login → bloqueio de 10 min
- **Pergunta de segurança (2FA offline)** – configurável via painel
- **Rotação automática de chave** – forward secrecy

### 🖥️ Painel administrativo
- **Criação de salas** – nome, senha opcional, modo efêmero
- **Gestão de membros** – promover, rebaixar, kick, mute, unmute, ban
- **Logs de acesso e moderação** – `modlog.json` e `acesso.log`
- **Blocklist** – bloqueio por nome de usuário
- **Alteração de senha admin** com hash seguro
- **Modo daemon** – `python3 ps.chat-adm.py --daemon`

### 💬 Comunicação
- **WebSocket (Socket.IO)** – retransmissão cega (servidor não lê mensagens E2EE)
- **Histórico persistente** – mensagens de sistema/texto plano (criptografadas não são armazenadas)
- **Salas efêmeras** – somem quando o último membro sai
- **Descoberta mDNS** – clientes encontram o servidor automaticamente

---

## 🚀 Instalação

### Pré‑requisitos

| Ambiente | Requisitos |
|----------|------------|
| **Termux (Android)** | `pkg update && pkg install python python-cryptography` |
| **Linux/macOS** | Python 3.9+ |
| **Windows** | WSL ou Python direto |

### 1. Clone o repositório

```bash
git clone https://github.com/PSecurity/ps.chat-admin
cd ps.chat-admin
```

### 2. Instale as dependências

```bash
pip install -r requirements.txt
```

**Dependências:**
```
· flask>=2.3,<3.0
· flask-socketio>=5.3,<6.0
· python-socketio>=5.11,<6.0
· werkzeug>=3.0,<4.0
```

### 3. Execute o servidor

```bash
python3 ps.chat-adm.py
```

**Na primeira execução, o arquivo `admin.hash` será criado com a senha padrão:**

```
🔐 Senha padrão: PeekAdmin2025
```

**⚠️ Altere a senha imediatamente após o primeiro acesso no painel admin!**

---

## 📖 Como usar

### Acessar como administrador

1. No navegador, acesse:
   ```
   http://localhost:5000/admin/login
   ```
2. Faça login com a senha (padrão: `PeekAdmin2025`)
3. No painel:
   - **Criar sala** – nome, senha (opcional) e marcar "Sala efêmera" se desejado
   - **Copiar token** – clique no token para copiar
   - **Gerir sala** – clique em "GERIR" para acessar o painel de moderação (promover, kick, ban, mute, etc.)
   - **Excluir sala**
4. **Alterar senha** – no painel "ALTERAR SENHA"
5. **Configurar pergunta de segurança** – em "🔒 SEGURANÇA"

### Usuários acessarem uma sala

Opções para os participantes:

| Método | Como fazer |
|--------|------------|
| Link direto | `http://<IP_DO_SERVIDOR>:5000/chat/<TOKEN>` (chat web descontinuado) |
| Cliente Python | `python3 pschat.py` (do repositório **ps.chat-cli**) |
| Cliente APK (em breve) | Aplicativo Android nativo com E2EE |

---

## 🧩 Estrutura do projeto

```
ps.chat-admin/
├── ps.chat-adm.py              # Servidor principal
├── requirements.txt            # Dependências Python
├── admin.hash                  # Hash da senha admin (criado automaticamente)
├── secret.key                  # Chave secreta persistente (sessões)
├── salas.json                  # Salas ativas (persistente)
├── modlog.json                 # Histórico de moderação
├── blocked_names.json          # Nomes bloqueados
├── banned_keys.json            # Chaves públicas banidas
├── banned_devices.json         # IDs de dispositivos banidos
├── logs/
│   └── acesso.log              # Logs de acesso e eventos
├── historico/
│   └── sala_TOKEN.json         # Histórico de mensagens por sala
└── templates/
    ├── admin_login.html
    ├── admin_dashboard.html
    ├── admin_logs.html
    ├── admin_modlog.html
    ├── admin_sala.html
    ├── admin_setup_question.html
    ├── admin_blocked_names.html
    └── admin_invite.html
```

---

## 🛠️ Configuração avançada

### Alterar porta do servidor

Edite a última linha do `ps.chat-adm.py`:

```python
socketio.run(app, host='0.0.0.0', port=8080, debug=False, allow_unsafe_werkzeug=True)
```

### Executar em segundo plano (modo daemon)

```bash
python3 ps.chat-adm.py --daemon &
```

O servidor continuará rodando mesmo após fechar o terminal.

### Resetar senha do admin

Delete o arquivo `admin.hash` e reinicie o servidor:

```bash
rm admin.hash
python3 ps.chat-adm.py
```

*A senha voltará a ser `PeekAdmin2025`.*

---

## 🐛 Troubleshooting

| Problema | Solução |
|----------|---------|
| `Address already in use` | Porta ocupada. Altere a porta ou mate o processo: `kill $(lsof -t -i:5000)` |
| Cliente não acessa a sala | Verifique se estão na mesma rede Wi‑Fi. Use `ip a` no Termux para ver o IP correto. |
| WebSocket não conecta | Instale as versões corretas: `pip install -r requirements.txt` |
| Login admin não funciona | Verifique o arquivo `admin.hash`. Se necessário, delete e reinicie. |
| Botões do painel não funcionam | Verifique se o servidor foi iniciado com `python3 ps.chat-adm.py` (não use `flask run`). |
| Erro `Pillow` | O QR code foi removido. Ignore mensagens sobre Pillow. |
| **Termux: erro ao instalar `cryptography`** | Use `pkg install python-cryptography` antes do `pip install`. |

---

## 📡 Como outros dispositivos encontram o servidor?

- **Manual:** Informe o IP do servidor. No Termux, execute `ip a` ou `ifconfig`.
- **Automática (mDNS):** O servidor se anuncia na rede como `PS.Chat._pschat._tcp.local`. Clientes com `zeroconf` detectam automaticamente.

---

## 🔒 Segurança

- Senha admin armazenada com hash (werkzeug/scrypt)
- Tokens de sala gerados com `secrets.token_hex(4)` (criptograficamente seguros)
- Chave de sala nunca exposta ao servidor
- Assinatura digital Ed25519 em todas as mensagens
- Banimento por chave pública e ID de dispositivo
- Rate limiting e pergunta de segurança (2FA offline)

---

## 🧪 Testado em

| Plataforma | Navegador | Status |
|------------|-----------|--------|
| Termux (Android 12+) | Chrome, Kiwi Browser, Firefox | ✅ |
| Ubuntu 22.04 | Firefox, Chrome | ✅ |
| Windows 11 (WSL) | Edge, Chrome | ✅ |
| macOS | Safari, Chrome | ✅ |

---

## 🤝 Contribuindo

1. Faça um fork do projeto
2. Crie uma branch (`git checkout -b feature/nova-feature`)
3. Commit suas alterações (`git commit -m 'Adiciona nova feature'`)
4. Push para a branch (`git push origin feature/nova-feature`)
5. Abra um Pull Request

---

## 📄 Licença

Distribuído sob a licença MIT. Veja `LICENSE` para mais informações.

---

## 🙋 Suporte

- Abra uma issue no [GitHub Issues](https://github.com/PSecurity/ps.chat-admin/issues)
- Consulte o repositório cliente: [ps.chat-cli](https://github.com/PSecurity/ps.chat-cli)

---

**Desenvolvido por `PeekSecurity` – Comunicação offline, simples e segura.**
```
