#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os, json, secrets, webbrowser, html
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, Response
from flask_socketio import SocketIO, emit, join_room, leave_room
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

# ---------- Configurações ----------
HISTORICO_DIR = 'historico'
LOGS_DIR = 'logs'
LOG_FILE = os.path.join(LOGS_DIR, 'acesso.log')
ADMIN_HASH_FILE = 'admin.hash'
SECRET_FILE = 'secret.key'
SALAS_FILE = 'salas.json'
SENHA_PADRAO = 'PeekAdmin2025'

app = Flask(__name__)
socketio = SocketIO(app, async_mode='threading')
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)

os.makedirs(LOGS_DIR, exist_ok=True)
os.makedirs(HISTORICO_DIR, exist_ok=True)

# ---------- Helpers (mesmos das versões anteriores) ----------
def carregar_ou_gerar_chave():
    if os.path.exists(SECRET_FILE):
        with open(SECRET_FILE) as f: return f.read().strip()
    chave = secrets.token_hex(32)
    with open(SECRET_FILE, 'w') as f: f.write(chave)
    try: os.chmod(SECRET_FILE, 0o600)
    except: pass
    return chave
app.config['SECRET_KEY'] = carregar_ou_gerar_chave()

def carregar_hash_admin():
    if os.path.exists(ADMIN_HASH_FILE):
        with open(ADMIN_HASH_FILE) as f: return f.read().strip()
    h = generate_password_hash(SENHA_PADRAO)
    with open(ADMIN_HASH_FILE, 'w') as f: f.write(h)
    try: os.chmod(ADMIN_HASH_FILE, 0o600)
    except: pass
    return h

def salvar_hash_admin(novo_hash):
    with open(ADMIN_HASH_FILE, 'w') as f: f.write(novo_hash)
    try: os.chmod(ADMIN_HASH_FILE, 0o600)
    except: pass

def log_acesso(acao, token="", detalhe=""):
    agora = datetime.now().isoformat()
    ip = request.remote_addr
    with open(LOG_FILE, 'a') as f: f.write(f"{agora} | {acao} | {ip} | {token} | {detalhe}\n")

def carregar_historico(token):
    caminho = os.path.join(HISTORICO_DIR, f'sala_{token}.json')
    if os.path.exists(caminho):
        with open(caminho) as f: return json.load(f)
    return []

def salvar_historico(token, hist):
    if len(hist) > 200:
        hist = hist[-200:]
    with open(os.path.join(HISTORICO_DIR, f'sala_{token}.json'), 'w') as f:
        json.dump(hist, f, indent=2)

def carregar_salas():
    if not os.path.exists(SALAS_FILE): return {}
    try:
        with open(SALAS_FILE) as f: return json.load(f)
    except: return {}

def salvar_salas(salas_dict):
    with open(SALAS_FILE, 'w') as f: json.dump(salas_dict, f, indent=2)

salas = carregar_salas()
usuarios = {}                    # sid -> {token, username, pubkey, sign_pubkey, admin, moderator}

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('admin_auth'): return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated

# ---------- Rotas Admin ----------
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    erro = None
    if request.method == 'POST':
        senha = request.form.get('senha', '')
        if check_password_hash(carregar_hash_admin(), senha):
            session['admin_auth'] = True
            session.permanent = True
            log_acesso('LOGIN_ADMIN')
            return redirect(url_for('admin_dashboard'))
        else:
            log_acesso('FALHA_LOGIN_ADMIN')
            erro = 'Senha incorreta.'
    return render_template('admin_login.html', erro=erro)

@app.route('/admin/logout')
def admin_logout():
    session.pop('admin_auth', None)
    return redirect(url_for('admin_login'))

@app.route('/admin')
@admin_required
def admin_dashboard():
    return render_template('admin_dashboard.html', salas=salas)

@app.route('/admin/criar_sala', methods=['POST'])
@admin_required
def criar_sala():
    nome = request.form.get('nome', 'Sala sem nome').strip()[:50]
    senha = request.form.get('senha', '').strip()
    token = secrets.token_hex(4)
    sala = {"nome": nome, "criador": request.remote_addr}
    if senha:
        sala['senha_hash'] = generate_password_hash(senha)
    salas[token] = sala
    salvar_salas(salas)
    log_acesso('CRIAR_SALA', token, f'Nome: {nome}, Protegida: {bool(senha)}')
    return jsonify({'token': token, 'nome': nome})

@app.route('/admin/excluir_sala/<token>', methods=['DELETE'])
@admin_required
def excluir_sala(token):
    if token in salas:
        nome = salas[token]['nome']
        del salas[token]
        salvar_salas(salas)
        log_acesso('EXCLUIR_SALA', token, f'Nome: {nome}')
        return jsonify({'status': 'ok'})
    return jsonify({'status': 'erro', 'mensagem': 'Sala não encontrada'}), 404

@app.route('/admin/listar_salas')
@admin_required
def listar_salas():
    return jsonify(salas)

@app.route('/admin/logs')
@admin_required
def admin_logs():
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE) as f:
            linhas = f.readlines()[-200:]
            linhas.reverse()
        return render_template('admin_logs.html', logs=linhas)
    return render_template('admin_logs.html', logs=[])

@app.route('/admin/alterar_senha', methods=['POST'])
@admin_required
def alterar_senha():
    atual = request.form.get('senha_atual', '')
    nova = request.form.get('nova_senha', '')
    if len(nova) < 6:
        return jsonify({'status': 'erro', 'mensagem': 'Nova senha deve ter pelo menos 6 caracteres.'})
    if not check_password_hash(carregar_hash_admin(), atual):
        log_acesso('FALHA_ALTERAR_SENHA')
        return jsonify({'status': 'erro', 'mensagem': 'Senha atual incorreta.'})
    salvar_hash_admin(generate_password_hash(nova))
    session.pop('admin_auth', None)
    log_acesso('SENHA_ALTERADA')
    return jsonify({'status': 'ok'})

@app.route('/admin/gerar_qrcode/<token>')
@admin_required
def admin_gerar_qrcode(token):
    if token not in salas: return "Sala não encontrada", 404
    import qrcode, io
    img = qrcode.make(token)
    buf = io.BytesIO()
    img.save(buf, format='PNG')
    buf.seek(0)
    return Response(buf.getvalue(), mimetype='image/png')

# ---------- Nova rota para gerenciar sala ----------
@app.route('/admin/sala/<token>')
@admin_required
def admin_sala(token):
    if token not in salas: return "Sala não encontrada", 404
    # Coleta membros da sala
    membros = []
    for sid, u in usuarios.items():
        if u.get('token') == token:
            membros.append({
                'username': u['username'],
                'admin': u.get('admin', False),
                'moderator': u.get('moderator', False),
                'has_pubkey': bool(u.get('pubkey'))
            })
    return render_template('admin_sala.html', token=token, nome_sala=salas[token]['nome'], membros=membros)

@app.route('/admin/sala/<token>/acao', methods=['POST'])
@admin_required
def admin_sala_acao(token):
    if token not in salas: return jsonify({'status': 'erro', 'mensagem': 'Sala inválida'}), 404
    acao = request.form.get('acao')
    target = request.form.get('username')
    if not target or not acao:
        return jsonify({'status': 'erro', 'mensagem': 'Parâmetros insuficientes'}), 400

    # Encontra o sid do usuário alvo
    target_sid = None
    for sid, u in usuarios.items():
        if u.get('token') == token and u['username'] == target:
            target_sid = sid
            break
    if not target_sid:
        return jsonify({'status': 'erro', 'mensagem': 'Usuário não encontrado'}), 404

    if acao == 'kick':
        # Remove o usuário da sala
        socketio.emit('kick', {'mensagem': 'Você foi removido da sala.'}, room=target_sid)
        leave_room(target_sid, token)
        usuarios.pop(target_sid, None)
        log_acesso('KICK', token, f'Usuário {target} removido')
        return jsonify({'status': 'ok'})
    elif acao == 'promote':
        if target_sid in usuarios:
            usuarios[target_sid]['moderator'] = True
            emit('promoted', {'status': 'moderator'}, room=target_sid)
            log_acesso('PROMOTE', token, f'{target} promovido a moderador')
            return jsonify({'status': 'ok'})
    elif acao == 'demote':
        if target_sid in usuarios:
            usuarios[target_sid]['moderator'] = False
            emit('demoted', {}, room=target_sid)
            log_acesso('DEMOTE', token, f'{target} rebaixado')
            return jsonify({'status': 'ok'})
    elif acao == 'block':
        # Bloquear usuário (remover e impedir reentrada com mesmo nome por X minutos)
        # Simples: apenas remove agora
        socketio.emit('kick', {'mensagem': 'Você foi bloqueado da sala.'}, room=target_sid)
        leave_room(target_sid, token)
        usuarios.pop(target_sid, None)
        log_acesso('BLOCK', token, f'Usuário {target} bloqueado')
        return jsonify({'status': 'ok'})
    return jsonify({'status': 'erro', 'mensagem': 'Ação desconhecida'}), 400

# ---------- WebSocket ----------
@socketio.on('entrar')
def on_entrar(data):
    token = data.get('token')
    username = data.get('username', 'Anônimo')[:50]
    pubkey = data.get('pubkey')
    sign_pubkey = data.get('sign_pubkey')
    senha_sala = data.get('senha', '')
    senha_admin = data.get('senha_admin', '')

    if token not in salas:
        emit('erro', {'mensagem': 'Sala inválida.'})
        return

    sala = salas[token]
    if 'senha_hash' in sala:
        if not senha_sala or not check_password_hash(sala['senha_hash'], senha_sala):
            emit('erro', {'mensagem': 'Senha da sala incorreta.', 'tipo': 'senha_sala'})
            return

    join_room(token)

    is_admin = False
    if senha_admin and check_password_hash(carregar_hash_admin(), senha_admin):
        is_admin = True
        log_acesso('ADMIN_CLI', token, f'Usuário: {username}')

    usuarios[request.sid] = {
        'token': token,
        'username': username,
        'pubkey': pubkey,
        'sign_pubkey': sign_pubkey,
        'admin': is_admin,
        'moderator': False
    }

    prefix = "👑 Admin " if is_admin else ""
    msg_sistema = {
        'type': 'system',
        'user': '⚡ Sistema',
        'text': f'{html.escape(prefix + username)} entrou na sala.',
        'timestamp': datetime.now().isoformat()
    }
    hist = carregar_historico(token)
    hist.append(msg_sistema)
    salvar_historico(token, hist)
    socketio.emit('mensagem', msg_sistema, room=token)

    if is_admin:
        emit('admin_auth', {'status': 'ok'})

    if pubkey and sign_pubkey:
        socketio.emit('chave_publica', {
            'user': username,
            'pubkey': pubkey,
            'sign_pubkey': sign_pubkey
        }, room=token)

        for sid, u in usuarios.items():
            if u['token'] == token and u['pubkey'] and u['username'] != username:
                emit('chave_publica', {
                    'user': u['username'],
                    'pubkey': u['pubkey'],
                    'sign_pubkey': u['sign_pubkey']
                })

@socketio.on('mensagem')
def on_mensagem(data):
    token = data.get('token')
    if token not in salas: return

    user_info = usuarios.get(request.sid, {})
    if 'user' not in data:
        data['user'] = user_info.get('username', 'Anônimo')
    if user_info.get('admin'):
        data['admin'] = True
    if user_info.get('moderator'):
        data['moderator'] = True

    if 'ciphertext' not in data and 'text' in data:
        data['text'] = html.escape(data['text'][:2000])
        if not data.get('ephemeral'):
            hist = carregar_historico(token)
            hist.append(data)
            salvar_historico(token, hist)

    socketio.emit('mensagem', data, room=token)

@socketio.on('room_key')
def on_room_key(data):
    token = data.get('token')
    dest = data.get('destinatario')
    for sid, u in usuarios.items():
        if u['token'] == token and u['username'] == dest:
            emit('room_key', data, room=sid)
            break

@socketio.on('sala_info')
def on_sala_info(data):
    token = data.get('token')
    if token not in salas: return
    members = []
    for sid, u in usuarios.items():
        if u.get('token') == token:
            members.append({
                'username': u['username'],
                'has_pubkey': bool(u.get('pubkey')),
                'admin': u.get('admin', False),
                'moderator': u.get('moderator', False)
            })
    emit('sala_info', {'members': members})

@socketio.on('solicitar_chave')
def on_solicitar_chave(data):
    token = data.get('token')
    usuario = data.get('username')
    if token not in salas: return
    for sid, u in usuarios.items():
        if u['token'] == token and u['username'] == usuario and u['pubkey']:
            emit('chave_publica', {
                'user': u['username'],
                'pubkey': u['pubkey'],
                'sign_pubkey': u['sign_pubkey']
            })
            break

@socketio.on('kick_user')
def on_kick_user(data):
    """Admin ou moderador remove um usuário da sala."""
    token = data.get('token')
    target = data.get('username')
    user_info = usuarios.get(request.sid, {})
    if not user_info.get('admin') and not user_info.get('moderator'):
        emit('erro', {'mensagem': 'Sem permissão.'})
        return
    if token not in salas:
        return
    target_sid = None
    for sid, u in usuarios.items():
        if u.get('token') == token and u['username'] == target:
            target_sid = sid
            break
    if target_sid:
        socketio.emit('kick', {'mensagem': f'Você foi removido por {user_info["username"]}.'}, room=target_sid)
        leave_room(target_sid, token)
        usuarios.pop(target_sid, None)
        log_acesso('KICK_CMD', token, f'{target} removido por {user_info["username"]}')

@socketio.on('disconnect')
def on_disconnect():
    user = usuarios.pop(request.sid, None)
    if user:
        token = user['token']
        if token in salas:
            msg_sistema = {
                'type': 'system',
                'user': '⚡ Sistema',
                'text': f'{user["username"]} saiu da sala.',
                'timestamp': datetime.now().isoformat()
            }
            hist = carregar_historico(token)
            hist.append(msg_sistema)
            salvar_historico(token, hist)
            socketio.emit('mensagem', msg_sistema, room=token)
            log_acesso('SAIR_SALA', token, f'Usuário: {user["username"]}')

if __name__ == '__main__':
    print("🔥 PS.Chat Admin v2.0 iniciado em http://0.0.0.0:5000")
    webbrowser.open('http://localhost:5000/admin')
    socketio.run(app, host='0.0.0.0', port=5000, debug=False, allow_unsafe_werkzeug=True)
