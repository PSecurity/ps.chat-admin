#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os, json, secrets, webbrowser
from datetime import datetime
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

# Hash da senha admin
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

# Log
def log_acesso(acao, token="", detalhe=""):
    agora = datetime.now().isoformat()
    ip = request.remote_addr
    with open(LOG_FILE, 'a') as f: f.write(f"{agora} | {acao} | {ip} | {token} | {detalhe}\n")

# Histórico
def carregar_historico(token):
    caminho = os.path.join(HISTORICO_DIR, f'sala_{token}.json')
    if os.path.exists(caminho):
        with open(caminho) as f: return json.load(f)
    return []

def salvar_historico(token, hist):
    with open(os.path.join(HISTORICO_DIR, f'sala_{token}.json'), 'w') as f:
        json.dump(hist, f, indent=2)

# Salas persistentes
def carregar_salas():
    if not os.path.exists(SALAS_FILE): return {}
    try:
        with open(SALAS_FILE) as f: return json.load(f)
    except: return {}

def salvar_salas(salas_dict):
    with open(SALAS_FILE, 'w') as f: json.dump(salas_dict, f, indent=2)

salas = carregar_salas()
usuarios = {}  # sid: {token, username}

# Decorator admin
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
    token = secrets.token_hex(4)
    salas[token] = {"nome": nome, "criador": request.remote_addr}
    salvar_salas(salas)
    log_acesso('CRIAR_SALA', token, f'Nome: {nome}')
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

# ===== ROTA DO CHAT (USUÁRIO) =====
@app.route('/chat/<token>')
def chat(token):
    if token not in salas: return "Sala não encontrada ou expirada.", 404
    historico = carregar_historico(token)
    return render_template('chat.html', token=token, nome_sala=salas[token]['nome'], historico=historico)

# ===== WEBSOCKET =====
@socketio.on('entrar')
def on_entrar(data):
    token = data.get('token')
    username = data.get('username', 'Anônimo')[:50]
    if token not in salas:
        emit('erro', {'mensagem': 'Sala inválida.'})
        return
    join_room(token)
    usuarios[request.sid] = {'token': token, 'username': username}
    msg = {
        'user': '⚡ Sistema',
        'text': f'{username} entrou na sala.',
        'timestamp': datetime.now().isoformat()
    }
    hist = carregar_historico(token)
    hist.append(msg)
    salvar_historico(token, hist)
    socketio.emit('mensagem', msg, room=token)
    log_acesso('ENTRAR_SALA', token, f'Usuário: {username}')

@socketio.on('mensagem')
def on_mensagem(data):
    token = data.get('token')
    if token not in salas: return
    user = usuarios.get(request.sid, {})
    username = user.get('username', 'Anônimo')[:50]
    texto = data.get('text', '')[:2000]
    msg = {
        'user': username,
        'text': texto,
        'timestamp': data.get('timestamp', datetime.now().isoformat())
    }
    hist = carregar_historico(token)
    hist.append(msg)
    salvar_historico(token, hist)
    socketio.emit('mensagem', msg, room=token)

@socketio.on('disconnect')
def on_disconnect():
    user = usuarios.pop(request.sid, None)
    if user:
        token = user['token']
        if token in salas:
            msg = {
                'user': '⚡ Sistema',
                'text': f'{user["username"]} saiu da sala.',
                'timestamp': datetime.now().isoformat()
            }
            hist = carregar_historico(token)
            hist.append(msg)
            salvar_historico(token, hist)
            socketio.emit('mensagem', msg, room=token)
            log_acesso('SAIR_SALA', token, f'Usuário: {user["username"]}')

# ===== INÍCIO =====
if __name__ == '__main__':
    print("🔥 PS.Chat Admin v2.0 iniciado em http://0.0.0.0:5000")
    webbrowser.open('http://localhost:5000/admin')
    socketio.run(app, host='0.0.0.0', port=5000, debug=False, allow_unsafe_werkzeug=True)