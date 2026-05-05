#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os, json, secrets, webbrowser, html
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, Response
from flask_socketio import SocketIO, emit, join_room
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

# Configurações
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

# Chave secreta persistente
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
usuarios = {}

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('admin_auth'): return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated

# ========== ROTAS ==========

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
    senha_atual = request.form.get('senha_atual', '')
    nova_senha = request.form.get('nova_senha', '')
    if len(nova_senha) < 6:
        return jsonify({'status': 'erro', 'mensagem': 'Nova senha deve ter pelo menos 6 caracteres.'})
    if not check_password_hash(carregar_hash_admin(), senha_atual):
        log_acesso('FALHA_ALTERAR_SENHA')
        return jsonify({'status': 'erro', 'mensagem': 'Senha atual incorreta.'})
    salvar_hash_admin(generate_password_hash(nova_senha))
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

# ========== WEBSOCKET ==========

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

    # Verificar admin
    is_admin = False
    if senha_admin:
        if check_password_hash(carregar_hash_admin(), senha_admin):
            is_admin = True
            log_acesso('ADMIN_CLI', token, f'Usuário: {username} autenticado como admin')

    usuarios[request.sid] = {
        'token': token,
        'username': username,
        'pubkey': pubkey,
        'sign_pubkey': sign_pubkey,
        'admin': is_admin
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

    if 'text' in data and 'ciphertext' not in data:
        data['text'] = html.escape(data['text'][:2000])
        data['type'] = 'chat'
        data['timestamp'] = data.get('timestamp', datetime.now().isoformat())
        if not data.get('ephemeral', False):
            hist = carregar_historico(token)
            hist.append(data)
            salvar_historico(token, hist)

    socketio.emit('mensagem', data, room=token)

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
                'admin': u.get('admin', False)
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
