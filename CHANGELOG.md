# Changelog — PS.Chat

## v2.2.9 (2026-05-06)

### 🔒 Segurança
- E2EE com chave simétrica de sala (X25519 + AES‑GCM + Ed25519)
- Mensagens diretas (DM) criptografadas individualmente
- Verificação de identidade por assinatura digital (`/verify`)
- Banimento permanente por chave pública e ID do dispositivo
- Rate limiting de login no painel admin (5 tentativas / 10 min)
- Pergunta de segurança (2FA offline) para o painel admin
- Rotação automática da chave de sala (forward secrecy)
- Lista de nomes bloqueados (blocklist)

### 🖥️ Painel administrativo (v2.2.9)
- Interface web minimalista com identidade PeekSecurity
- Criação e gerenciamento de salas (nome, senha, modo efêmero)
- Gestão de membros: promover, rebaixar, kick, mute, unmute, ban
- Logs de acesso e moderação (modlog)
- Configuração de pergunta de segurança
- Modo daemon (`--daemon`) para execução em segundo plano
- Exibição dos links de acesso (localhost e rede)

### 📟 Cliente terminal (v2.2.6)
- Conexão via Socket.IO com descoberta mDNS
- Fingerprint visual para verificação presencial
- Histórico local criptografado (`/log`)
- Envio de arquivos (`/send`)
- Mensagens efêmeras (`/sumir`)
- Subcanais com filtro (`/filter`)
- Autocompletar comandos (Tab)

### 🔧 Correções (v2.2.7 → v2.2.9)
- Botões do painel de gestão responsivos e dentro do layout
- Notificações de moderação (promote/demote/kick/ban) no chat
- Terminal não trava após desconexão
- Comandos `/log` retornam feedback claro
- Validação de IP/porta no cliente
- QR code removido (não funcional)
