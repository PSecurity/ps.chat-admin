# 👾 PS.Chat Admin

[![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)](https://github.com/seu-usuario/ps.chat-admin/releases)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.9%2B-yellow.svg)](https://python.org)
[![Termux](https://img.shields.io/badge/Termux-Compatible-red.svg)](https://termux.com)

**Servidor de chat privado, offline e com administração centralizada** – ideal para redes locais, eventos, equipes ou comunicação interna sem depender da internet.

---

## ✨ Funcionalidades

- 🔐 **Login administrativo seguro** – senha com hash (werkzeug), alterável via interface
- 🏠 **Gerenciamento de salas** – criar, listar e excluir salas com token único
- 💬 **Chat em tempo real** – WebSocket (Socket.IO) com histórico persistente
- 📱 **Interface responsiva** – funciona no PC, Android, iPhone (navegador)
- 🔑 **Token de acesso** – cada sala tem um token exclusivo de 8 caracteres
- 📲 **QR Code** – geração automática para facilitar entrada de usuários
- 📜 **Logs de acesso** – registra IPs, tokens usados, entradas/saídas
- 💾 **Histórico de mensagens** – persistente por sala (arquivos JSON)
- 🌐 **Descoberta mDNS** – clientes podem encontrar o servidor automaticamente

---

## 🚀 Instalação

### Pré-requisitos

| Ambiente | Requisitos |
|----------|------------|
| **Termux (Android)** | `pkg update && pkg install python` |
| **Linux/macOS** | Python 3.9+ |
| **Windows** | WSL ou Python direto |

### 1. Clone o repositório

```bash
git clone https://github.com/seu-usuario/ps.chat-admin.git
cd ps.chat-admin
```

2. Instale as dependências

```bash
pip install -r requirements.txt
```

Dependências:

· flask==2.3.3
· flask-socketio==5.3.4
· eventlet==0.33.3
· zeroconf==0.131.0

3. Execute o servidor

```bash
python ps.chat-adm.py
```

Na primeira execução, o arquivo admin.hash será criado com a senha padrão:

```
🔐 Senha padrão: PeekAdmin2025
```

⚠️ Altere a senha imediatamente após o primeiro acesso no painel admin!

---

📖 Como usar

Acessar como administrador

1. No navegador (do mesmo dispositivo que roda o servidor), acesse:
   ```
   http://localhost:5000/admin/login
   ```
2. Faça login com a senha (padrão: PeekAdmin2025)
3. No painel:
   · Criar sala – digite um nome e clique em "CRIAR SALA"
   · Copiar token – clique no token para copiar
   · QR Code – clique em "QR" para gerar código de acesso
   · Fechar sala – encerra a sala e desconecta todos os usuários
4. Alterar senha – acesse "ALTERAR SENHA" no cabeçalho

Usuários acessarem uma sala

Opções para os participantes:

Método Como fazer
Link direto http://<IP_DO_SERVIDOR>:5000/sala/<TOKEN>
Tela de entrada http://<IP_DO_SERVIDOR>:5000/ + digitar token
QR Code Escanear o QR gerado pelo admin
Cliente Python Usar ps.chat-cli.py do repositório cliente

---

🧩 Estrutura do projeto

```
ps.chat-admin/
├── ps.chat-adm.py           # Servidor principal
├── ps.chat-mdns.py          # Anúncio mDNS (descoberta automática)
├── requirements.txt         # Dependências Python
├── admin.hash               # Hash da senha admin (criado automaticamente)
├── logs/
│   └── acesso.log           # Logs de acesso e eventos
├── historico/
│   └── sala_TOKEN.json      # Histórico de mensagens por sala
└── templates/
    ├── admin.html
    ├── admin_login.html
    ├── admin_alterar_senha.html
    ├── entrar.html
    └── sala.html
```

---

🛠️ Configuração avançada

Alterar porta do servidor

Edite a última linha do ps.chat-adm.py:

```python
socketio.run(app, host='0.0.0.0', port=8080, ...)
```

Executar anúncio mDNS em segundo plano

```bash
python ps.chat-mdns.py &
```

Resetar senha do admin

Delete o arquivo admin.hash e reinicie o servidor:

```bash
rm admin.hash
python ps.chat-adm.py
```

A senha voltará a ser PeekAdmin2025.

---

🐛 Troubleshooting

Problema Solução
Erro Address already in use Porta 5000 ocupada. Altere a porta no código ou mate o processo: kill $(lsof -t -i:5000)
Cliente não acessa a sala Verifique se estão na mesma rede Wi-Fi. Use ifconfig no Termux para ver o IP correto.
WebSocket não conecta Instale a versão correta: pip install flask-socketio==5.3.4 eventlet==0.33.3
Login admin não funciona Verifique o arquivo admin.hash. Se necessário, delete e reinicie.
Mensagens não aparecem Abra o console do navegador (F12) e veja se há erros JavaScript.

---

📡 Como outros dispositivos encontram o servidor?

Opção 1 (manual): Informe o IP do servidor. No Termux, execute ifconfig ou ip a.

Opção 2 (automática com mDNS): O servidor se anuncia na rede como PS.Chat._pschat._tcp.local. Clientes com zeroconf (ex: ps.chat-cli.py) detectam automaticamente.

---

🔒 Segurança

· Senha admin armazenada com hash (werkzeug/scrypt)
· Tokens de sala gerados com secrets.token_hex(4) (criptograficamente seguros)
· Logs detalhados de acesso
· As mensagens trafegam em texto plano – para ambientes confidenciais, use HTTPS + autenticação adicional

---

🧪 Testado em

Plataforma Navegador Status
Termux (Android 12+) Chrome, Kiwi Browser, Firefox ✅
Ubuntu 22.04 Firefox, Chrome ✅
Windows 11 (WSL) Edge, Chrome ✅
macOS Safari, Chrome ✅

---

🤝 Contribuindo

1. Faça um fork do projeto
2. Crie uma branch (git checkout -b feature/nova-feature)
3. Commit suas alterações (git commit -m 'Adiciona nova feature')
4. Push para a branch (git push origin feature/nova-feature)
5. Abra um Pull Request

---

📄 Licença

Distribuído sob a licença MIT. Veja LICENSE para mais informações.

---

🙋 Suporte

· Abra uma issue no GitHub Issues
· Consulte o repositório cliente para scripts de acesso

---

Desenvolvido por PeekSecurity – Comunicação offline, simples e segura.
