#!/usr/bin/env python3
# ps.chat-adm.py - Servidor PS.Chat com alteração de senha via interface

import secrets
import time
import json
import os
from datetime import datetime
from functools import wraps
from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash
from flask_socketio import SocketIO, join_room, leave_room, send, emit
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(16)
socketio = SocketIO(app, cors_allowed_origins="*")

# Arquivo para armazenar o hash da senha
ADMIN_HASH_FILE = "admin.hash"

def carregar_hash_admin():
    """Carrega o hash da senha do arquivo. Se não existir, cria com a senha padrão."""
    if not os.path.exists(ADMIN_HASH_FILE):
        hash_padrao = generate_password_hash('PeekAdmin2025')
        with open(ADMIN_HASH_FILE, "w") as f:
            f.write(hash_padrao)
        return hash_padrao
    with open(ADMIN_HASH_FILE, "r") as f:
        return f.read().strip()

def salvar_hash_admin(novo_hash):
    """Salva o novo hash no arquivo."""
    with open(ADMIN_HASH_FILE, "w") as f:
        f.write(novo_hash)

ADMIN_HASH = carregar_hash_admin()

# Pastas de log e histórico
LOG_DIR = "logs"
HIST_DIR = "historico"
os.makedirs(LOG_DIR, exist_ok=True)
os.makedirs(HIST_DIR, exist_ok=True)

salas = {}

def log_acesso(tipo, ip, token=None, detalhe=""):
    log_file = os.path.join(LOG_DIR, "acesso.log")
    with open(log_file, "a", encoding="utf-8") as f:
        f.write(f"{datetime.now().isoformat()} | {tipo} | IP: {ip} | Token: {token} | {detalhe}\n")

def carregar_historico(token):
    hist_file = os.path.join(HIST_DIR, f"sala_{token}.json")
    if os.path.exists(hist_file):
        with open(hist_file, "r", encoding="utf-8") as f:
            return json.load(f)
    return []

def salvar_historico(token, mensagem):
    hist_file = os.path.join(HIST_DIR, f"sala_{token}.json")
    historico = carregar_historico(token)
    historico.append(mensagem)
    with open(hist_file, "w", encoding="utf-8") as f:
        json.dump(historico, f, indent=2, ensure_ascii=False)

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('admin_auth'):
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated

# ------------------ ADMIN: LOGIN ------------------
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        senha = request.form.get('senha')
        if check_password_hash(ADMIN_HASH, senha):
            session['admin_auth'] = True
            log_acesso("ADMIN_LOGIN_SUCESSO", request.remote_addr)
            return redirect(url_for('admin_panel'))
        else:
            log_acesso("ADMIN_LOGIN_FALHA", request.remote_addr, detalhe="Senha incorreta")
            return render_template('admin_login.html', erro="Senha incorreta")
    return render_template('admin_login.html')

@app.route('/admin/logout')
def admin_logout():
    session.pop('admin_auth', None)
    return redirect(url_for('admin_login'))

# ------------------ ADMIN: ALTERAR SENHA ------------------
@app.route('/admin/alterar_senha', methods=['GET', 'POST'])
@admin_required
def alterar_senha():
    global ADMIN_HASH
    if request.method == 'POST':
        senha_atual = request.form.get('senha_atual')
        nova_senha = request.form.get('nova_senha')
        confirmar_senha = request.form.get('confirmar_senha')
        
        # Validações
        if not check_password_hash(ADMIN_HASH, senha_atual):
            return render_template('admin_alterar_senha.html', erro="Senha atual incorreta")
        if len(nova_senha) < 6:
            return render_template('admin_alterar_senha.html', erro="A nova senha deve ter pelo menos 6 caracteres")
        if nova_senha != confirmar_senha:
            return render_template('admin_alterar_senha.html', erro="As senhas não coincidem")
        
        # Gera novo hash e salva
        novo_hash = generate_password_hash(nova_senha)
        salvar_hash_admin(novo_hash)
        ADMIN_HASH = novo_hash
        
        log_acesso("ADMIN_SENHA_ALTERADA", request.remote_addr)
        flash("Senha alterada com sucesso! Faça login novamente.", "success")
        session.pop('admin_auth', None)  # força logout para usar nova senha
        return redirect(url_for('admin_login'))
    
    return render_template('admin_alterar_senha.html')

# ------------------ ADMIN: PAINEL ------------------
@app.route('/admin')
@admin_required
def admin_panel():
    return render_template('admin.html', salas=salas)

@app.route('/admin/listar_salas')
@admin_required
def listar_salas():
    dados = []
    for token, info in salas.items():
        dados.append({
            "token": token,
            "nome": info['nome'],
            "usuarios": len(info['usuarios']),
            "criado_em": info['criado_em']
        })
    return jsonify(dados)

@app.route('/admin/criar_sala', methods=['POST'])
@admin_required
def criar_sala():
    dados = request.get_json()
    nome_sala = dados.get('nome', 'Sala sem nome')
    token = secrets.token_hex(4)
    salas[token] = {
        'nome': nome_sala,
        'usuarios': set(),
        'criado_em': time.time()
    }
    log_acesso("SALA_CRIADA", request.remote_addr, token, f"Nome: {nome_sala}")
    return jsonify({"token": token, "nome": nome_sala})

@app.route('/admin/excluir_sala/<token>', methods=['DELETE'])
@admin_required
def excluir_sala(token):
    if token in salas:
        socketio.emit('sala_fechada', {"msg": "Sala encerrada pelo administrador"}, room=token)
        del salas[token]
        log_acesso("SALA_EXCLUIDA", request.remote_addr, token)
        return jsonify({"ok": True})
    return jsonify({"erro": "sala não existe"}), 404

# ------------------ ROTAS PARA USUÁRIOS ------------------
@app.route('/')
def index():
    return render_template('entrar.html')

@app.route('/entrar', methods=['POST'])
def entrar_sala():
    token = request.form.get('token')
    if token not in salas:
        log_acesso("TOKEN_INVALIDO", request.remote_addr, token)
        return "❌ Token inválido. <a href='/'>Voltar</a>", 404
    log_acesso("USUARIO_REDIRECIONADO", request.remote_addr, token)
    return redirect(url_for('sala', token=token))

@app.route('/sala/<token>')
def sala(token):
    if token not in salas:
        return "Sala não encontrada", 404
    return render_template('sala.html', token=token, nome_sala=salas[token]['nome'])

# ------------------ WEBSOCKET ------------------
@socketio.on('entrar')
def on_entrar(data):
    token = data['token']
    if token not in salas:
        return
    username = data.get('username', 'Anônimo')
    join_room(token)
    salas[token]['usuarios'].add(request.sid)
    historico = carregar_historico(token)
    emit('historico', historico, room=request.sid)
    send({'user': '🔵 Sistema', 'text': f"{username} entrou", 'timestamp': ''}, room=token)
    log_acesso("WEBSOCKET_ENTROU", request.remote_addr, token, f"Usuário: {username}")

@socketio.on('mensagem')
def on_mensagem(data):
    token = data['token']
    if token not in salas:
        return
    msg = {
        'user': data['username'],
        'text': data.get('text', ''),
        'timestamp': data['timestamp']
    }
    if 'iv' in data and 'ciphertext' in data:
        msg['iv'] = data['iv']
        msg['ciphertext'] = data['ciphertext']
        msg['text'] = ''
    salvar_historico(token, msg)
    send(msg, room=token)

@socketio.on('sair')
def on_sair(data):
    token = data['token']
    if token in salas and request.sid in salas[token]['usuarios']:
        salas[token]['usuarios'].discard(request.sid)
        leave_room(token)
        username = data.get('username', 'Anônimo')
        send({'user': '⚫ Sistema', 'text': f"{username} saiu", 'timestamp': ''}, room=token)
        log_acesso("WEBSOCKET_SAIU", request.remote_addr, token, f"Usuário: {username}")

if __name__ == '__main__':
    print("\n" + "="*50)
    print("🔐 PS.Chat ADMIN - Senha padrão: PeekAdmin2025")
    print("📡 Painel admin: http://localhost:5000/admin/login")
    print("💬 Usuários: http://<SEU_IP>:5000/")
    print("="*50 + "\n")
    socketio.run(app, host='0.0.0.0', port=5000, debug=False, allow_unsafe_werkzeug=True)
