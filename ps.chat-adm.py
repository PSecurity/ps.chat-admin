#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os, json, secrets, webbrowser, html, time
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, Response
from flask_socketio import SocketIO, emit, join_room, leave_room
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

# ---------- Configurações ----------
HISTORICO_DIR = 'historico'
LOGS_DIR = 'logs'
LOG_FILE = os.path.join(LOGS_DIR, 'acesso.log')
MODLOG_FILE = 'modlog.json'
BLOCKED_NAMES_FILE = 'blocked_names.json'
BANNED_KEYS_FILE = 'banned_keys.json'
ADMIN_HASH_FILE = 'admin.hash'
SECRET_FILE = 'secret.key'
SECRET_QUESTION_FILE = 'secret_question.json'
SALAS_FILE = 'salas.json'
SENHA_PADRAO = 'PeekAdmin2025'
MAX_LOGIN_ATTEMPTS = 5
LOGIN_BLOCK_TIME = 600

app = Flask(__name__)
socketio = SocketIO(app, async_mode='threading')
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)

os.makedirs(LOGS_DIR, exist_ok=True)
os.makedirs(HISTORICO_DIR, exist_ok=True)

# ---------- Helpers (carregar/salvar) ----------
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

def salvar_modlog(acao, token, admin, target, detalhe=""):
    entrada = {
        "timestamp": datetime.now().isoformat(),
        "acao": acao, "token": token, "admin": admin,
        "target": target, "detalhe": detalhe
    }
    log_data = []
    if os.path.exists(MODLOG_FILE):
        with open(MODLOG_FILE) as f: log_data = json.load(f)
    log_data.append(entrada)
    if len(log_data) > 200: log_data = log_data[-200:]
    with open(MODLOG_FILE, 'w') as f: json.dump(log_data, f, indent=2)

def carregar_modlog():
    if os.path.exists(MODLOG_FILE):
        with open(MODLOG_FILE) as f: return json.load(f)
    return []

def carregar_blocked_names():
    if os.path.exists(BLOCKED_NAMES_FILE):
        with open(BLOCKED_NAMES_FILE) as f: return json.load(f)
    return []

def salvar_blocked_names(names_list):
    with open(BLOCKED_NAMES_FILE, 'w') as f: json.dump(names_list, f, indent=2)

def carregar_banned_keys():
    if os.path.exists(BANNED_KEYS_FILE):
        with open(BANNED_KEYS_FILE) as f: return json.load(f)
    return []

def salvar_banned_keys(keys_list):
    with open(BANNED_KEYS_FILE, 'w') as f: json.dump(keys_list, f, indent=2)

login_attempts = {}

def registrar_tentativa(ip):
    agora = time.time()
    if ip in login_attempts:
        tentativas, inicio = login_attempts[ip]
        if agora - inicio > LOGIN_BLOCK_TIME:
            login_attempts[ip] = [1, agora]
        else:
            tentativas += 1
            if tentativas > MAX_LOGIN_ATTEMPTS: return False
            login_attempts[ip] = [tentativas, inicio]
    else:
        login_attempts[ip] = [1, agora]
    return True

def ip_bloqueado(ip):
    if ip not in login_attempts: return False
    tentativas, inicio = login_attempts[ip]
    return tentativas > MAX_LOGIN_ATTEMPTS and (time.time() - inicio) < LOGIN_BLOCK_TIME

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
    if len(hist) > 200: hist = hist[-200:]
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
contador_mensagens = {}
ultima_rotacao = {}

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
    ip = request.remote_addr
    if request.method == 'POST':
        if ip_bloqueado(ip):
            erro = 'IP bloqueado por excesso de tentativas. Tente novamente mais tarde.'
            return render_template('admin_login.html', erro=erro, pergunta=None)
        senha = request.form.get('senha', '')
        if check_password_hash(carregar_hash_admin(), senha):
            if os.path.exists(SECRET_QUESTION_FILE):
                with open(SECRET_QUESTION_FILE) as f: qdata = json.load(f)
                resposta = request.form.get('resposta', '')
                if not resposta or not check_password_hash(qdata['hash_resposta'], resposta):
                    login_attempts.pop(ip, None)
                    return render_template('admin_login.html', erro='Resposta de segurança incorreta.', pergunta=qdata['pergunta'])
            session['admin_auth'] = True
            session.permanent = True
            login_attempts.pop(ip, None)
            log_acesso('LOGIN_ADMIN')
            return redirect(url_for('admin_dashboard'))
        else:
            if not registrar_tentativa(ip):
                erro = 'IP bloqueado por excesso de tentativas.'
            else:
                erro = 'Senha incorreta.'
    pergunta = None
    if os.path.exists(SECRET_QUESTION_FILE):
        with open(SECRET_QUESTION_FILE) as f:
            pergunta = json.load(f)['pergunta']
    return render_template('admin_login.html', erro=erro, pergunta=pergunta)

@app.route('/admin/setup_question', methods=['GET', 'POST'])
@admin_required
def setup_question():
    if request.method == 'POST':
        pergunta = request.form.get('pergunta', '').strip()
        resposta = request.form.get('resposta', '').strip()
        if not pergunta or not resposta:
            return render_template('admin_setup_question.html', erro='Preencha todos os campos.')
        qdata = {'pergunta': pergunta, 'hash_resposta': generate_password_hash(resposta)}
        with open(SECRET_QUESTION_FILE, 'w') as f: json.dump(qdata, f, indent=2)
        return redirect(url_for('admin_dashboard'))
    # GET – exibe formulário (se já existir, exibe pergunta atual)
    atual = None
    if os.path.exists(SECRET_QUESTION_FILE):
        with open(SECRET_QUESTION_FILE) as f: atual = json.load(f)['pergunta']
    return render_template('admin_setup_question.html', pergunta_atual=atual)

@app.route('/admin/remove_question', methods=['POST'])
@admin_required
def remove_question():
    if os.path.exists(SECRET_QUESTION_FILE):
        os.remove(SECRET_QUESTION_FILE)
    return redirect(url_for('admin_dashboard'))

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
    efemera = request.form.get('efemera') == 'on'
    token = secrets.token_hex(4)
    sala = {"nome": nome, "criador": request.remote_addr, "efemera": efemera}
    if senha:
        sala['senha_hash'] = generate_password_hash(senha)
    salas[token] = sala
    salvar_salas(salas)
    log_acesso('CRIAR_SALA', token, f'Nome: {nome}, Protegida: {bool(senha)}, Efêmera: {efemera}')
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

@app.route('/admin/modlog')
@admin_required
def admin_modlog():
    logs = carregar_modlog()
    logs.reverse()
    return render_template('admin_modlog.html', logs=logs[:200])

@app.route('/admin/blocked_names', methods=['GET','POST'])
@admin_required
def admin_blocked_names():
    if request.method == 'POST':
        lista = request.form.get('nomes', '').split(',')
        lista = [n.strip() for n in lista if n.strip()]
        salvar_blocked_names(lista)
        return redirect(url_for('admin_blocked_names'))
    nomes = carregar_blocked_names()
    return render_template('admin_blocked_names.html', nomes=nomes)

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

@app.route('/admin/invite/<token>')
@admin_required
def admin_invite(token):
    if token not in salas: return "Sala não encontrada", 404
    base = request.host_url.rstrip('/')
    link = f"{base}/chat?token={token}"
    return render_template('admin_invite.html', link=link, token=token)

@app.route('/admin/sala/<token>')
@admin_required
def admin_sala(token):
    if token not in salas: return "Sala não encontrada", 404
    membros = []
    for sid, u in usuarios.items():
        if u.get('token') == token:
            membros.append({
                'username': u['username'],
                'admin': u.get('admin', False),
                'moderator': u.get('moderator', False),
                'muted': u.get('muted', False),
                'has_pubkey': bool(u.get('pubkey'))
            })
    return render_template('admin_sala.html', token=token, nome_sala=salas[token]['nome'], membros=membros)

@app.route('/admin/sala/<token>/acao', methods=['POST'])
@admin_required
def admin_sala_acao(token):
    if token not in salas: return jsonify({'status': 'erro', 'mensagem': 'Sala inválida'}), 404
    acao = request.form.get('acao')
    target = request.form.get('username')
    if not target or not acao: return jsonify({'status': 'erro', 'mensagem': 'Parâmetros insuficientes'}), 400

    target_sid = None
    for sid, u in usuarios.items():
        if u.get('token') == token and u['username'] == target:
            target_sid = sid
            break
    if not target_sid: return jsonify({'status': 'erro', 'mensagem': 'Usuário não encontrado'}), 404

    if acao == 'kick':
        emit('kick', {'mensagem': 'Você foi removido da sala.'}, room=target_sid)
        leave_room(target_sid, token)
        usuarios.pop(target_sid, None)
        salvar_modlog('kick', token, 'admin_web', target)
        _rotacionar_sala(token)
        return jsonify({'status': 'ok'})
    elif acao == 'promote':
        if target_sid in usuarios:
            usuarios[target_sid]['moderator'] = True
            emit('promoted', {}, room=target_sid)
            salvar_modlog('promote', token, 'admin_web', target)
            return jsonify({'status': 'ok'})
    elif acao == 'demote':
        if target_sid in usuarios:
            usuarios[target_sid]['moderator'] = False
            emit('demoted', {}, room=target_sid)
            salvar_modlog('demote', token, 'admin_web', target)
            return jsonify({'status': 'ok'})
    elif acao == 'block':
        # Adicionar chave pública à banned_keys
        chave = usuarios[target_sid].get('pubkey')
        if chave:
            banned = carregar_banned_keys()
            if chave not in banned:
                banned.append(chave)
                salvar_banned_keys(banned)
        emit('kick', {'mensagem': 'Você foi bloqueado da sala.'}, room=target_sid)
        leave_room(target_sid, token)
        usuarios.pop(target_sid, None)
        salvar_modlog('block', token, 'admin_web', target)
        _rotacionar_sala(token)
        return jsonify({'status': 'ok'})
    elif acao == 'mute':
        if target_sid in usuarios:
            usuarios[target_sid]['muted'] = True
            emit('muted', {}, room=target_sid)
            salvar_modlog('mute', token, 'admin_web', target)
            return jsonify({'status': 'ok'})
    elif acao == 'unmute':
        if target_sid in usuarios:
            usuarios[target_sid]['muted'] = False
            emit('unmuted', {}, room=target_sid)
            salvar_modlog('unmute', token, 'admin_web', target)
            return jsonify({'status': 'ok'})
    return jsonify({'status': 'erro', 'mensagem': 'Ação desconhecida'}), 400

def _rotacionar_sala(token):
    """Após remoção de um membro, solicita renovação da chave da sala."""
    if token in salas:
        socketio.emit('rotate_key', {}, room=token)

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

    # Verificar ban por chave pública
    if pubkey and pubkey in carregar_banned_keys():
        emit('erro', {'mensagem': 'Sua chave está banida.'})
        return

    blocked = carregar_blocked_names()
    if username in blocked:
        emit('erro', {'mensagem': 'Nome de usuário bloqueado.'})
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
        'token': token, 'username': username, 'pubkey': pubkey,
        'sign_pubkey': sign_pubkey, 'admin': is_admin,
        'moderator': False, 'muted': False, 'join_time': time.time()
    }

    prefix = "👑 Admin " if is_admin else ""
    msg_sistema = {
        'type': 'system', 'user': '⚡ Sistema',
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
            'user': username, 'pubkey': pubkey, 'sign_pubkey': sign_pubkey
        }, room=token)
        for sid, u in usuarios.items():
            if u['token'] == token and u['pubkey'] and u['username'] != username:
                emit('chave_publica', {
                    'user': u['username'], 'pubkey': u['pubkey'], 'sign_pubkey': u['sign_pubkey']
                })

@socketio.on('mensagem')
def on_mensagem(data):
    token = data.get('token')
    if token not in salas: return

    user_info = usuarios.get(request.sid, {})
    if user_info.get('muted'):
        emit('erro', {'mensagem': 'Você está silenciado.'}); return

    if 'user' not in data:
        data['user'] = user_info.get('username', 'Anônimo')
    if user_info.get('admin'): data['admin'] = True
    if user_info.get('moderator'): data['moderator'] = True

    # DM – entrega apenas para o destinatário
    dm_target = data.get('dm_target')
    if dm_target:
        for sid, u in usuarios.items():
            if u['token'] == token and u['username'] == dm_target:
                emit('mensagem', data, room=sid)
                break
        return

    if 'text' in data and 'ciphertext' not in data:
        data['text'] = html.escape(data['text'][:2000])
        if not data.get('ephemeral'):
            hist = carregar_historico(token)
            hist.append(data)
            salvar_historico(token, hist)

    socketio.emit('mensagem', data, room=token)

    # Rotação automática
    if 'room_encrypted' in data:
        contador = contador_mensagens.get(token, 0) + 1
        contador_mensagens[token] = contador
        agora = time.time()
        if token not in ultima_rotacao or (agora - ultima_rotacao[token] > 600 or contador % 50 == 0):
            ultima_rotacao[token] = agora
            socketio.emit('rotate_key', {}, room=token)

@socketio.on('verify_request')
def on_verify_request(data):
    token = data.get('token')
    target = data.get('target')
    for sid, u in usuarios.items():
        if u['token'] == token and u['username'] == target:
            emit('verify_request', data, room=sid)
            break

@socketio.on('verify_response')
def on_verify_response(data):
    token = data.get('token')
    requester = data.get('requester')
    for sid, u in usuarios.items():
        if u['token'] == token and u['username'] == requester:
            emit('verify_response', data, room=sid)
            break

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
                'moderator': u.get('moderator', False),
                'muted': u.get('muted', False)
            })
    emit('sala_info', {'members': members})

@socketio.on('solicitar_chave')
def on_solicitar_chave(data):
    token = data.get('token')
    usuario = data.get('username')
    for sid, u in usuarios.items():
        if u['token'] == token and u['username'] == usuario and u['pubkey']:
            emit('chave_publica', {'user': u['username'], 'pubkey': u['pubkey'], 'sign_pubkey': u['sign_pubkey']})
            break

@socketio.on('kick_user')
def on_kick_user(data):
    token = data.get('token')
    target = data.get('username')
    user_info = usuarios.get(request.sid, {})
    if not user_info.get('admin') and not user_info.get('moderator'):
        emit('erro', {'mensagem': 'Sem permissão.'}); return
    target_sid = None
    for sid, u in usuarios.items():
        if u['token'] == token and u['username'] == target:
            target_sid = sid; break
    if target_sid:
        emit('kick', {'mensagem': f'Você foi removido por {user_info["username"]}.'}, room=target_sid)
        leave_room(target_sid, token)
        usuarios.pop(target_sid, None)
        salvar_modlog('kick', token, user_info['username'], target)
        _rotacionar_sala(token)

@socketio.on('mute_user')
def on_mute_user(data):
    token = data.get('token')
    target = data.get('username')
    user_info = usuarios.get(request.sid, {})
    if not user_info.get('admin') and not user_info.get('moderator'): return
    for sid, u in usuarios.items():
        if u['token'] == token and u['username'] == target:
            usuarios[sid]['muted'] = True
            emit('muted', {}, room=sid)
            salvar_modlog('mute', token, user_info['username'], target)
            break

@socketio.on('unmute_user')
def on_unmute_user(data):
    token = data.get('token')
    target = data.get('username')
    user_info = usuarios.get(request.sid, {})
    if not user_info.get('admin') and not user_info.get('moderator'): return
    for sid, u in usuarios.items():
        if u['token'] == token and u['username'] == target:
            usuarios[sid]['muted'] = False
            emit('unmuted', {}, room=sid)
            salvar_modlog('unmute', token, user_info['username'], target)
            break

@socketio.on('ban_user')
def on_ban_user(data):
    token = data.get('token')
    target = data.get('username')
    user_info = usuarios.get(request.sid, {})
    if not user_info.get('admin') and not user_info.get('moderator'):
        emit('erro', {'mensagem': 'Sem permissão.'}); return
    target_sid = None
    for sid, u in usuarios.items():
        if u['token'] == token and u['username'] == target:
            target_sid = sid; break
    if target_sid and usuarios[target_sid].get('pubkey'):
        chave = usuarios[target_sid]['pubkey']
        banned = carregar_banned_keys()
        if chave not in banned:
            banned.append(chave)
            salvar_banned_keys(banned)
        emit('kick', {'mensagem': f'Você foi banido por {user_info["username"]}.'}, room=target_sid)
        leave_room(target_sid, token)
        usuarios.pop(target_sid, None)
        salvar_modlog('ban', token, user_info['username'], target, f'pubkey: {chave[:20]}...')
        _rotacionar_sala(token)

@socketio.on('disconnect')
def on_disconnect():
    user = usuarios.pop(request.sid, None)
    if user:
        token = user['token']
        if token in salas:
            msg_sistema = {
                'type': 'system', 'user': '⚡ Sistema',
                'text': f'{user["username"]} saiu da sala.',
                'timestamp': datetime.now().isoformat()
            }
            hist = carregar_historico(token)
            hist.append(msg_sistema)
            salvar_historico(token, hist)
            socketio.emit('mensagem', msg_sistema, room=token)
            log_acesso('SAIR_SALA', token, f'Usuário: {user["username"]}')
            # Verificar sala vazia (efêmera)
            sala_ainda_tem = any(u.get('token') == token for u in usuarios.values())
            if not sala_ainda_tem and salas[token].get('efemera'):
                del salas[token]
                salvar_salas(salas)
                log_acesso('SALA_EFEMERA_REMOVIDA', token)

if __name__ == '__main__':
    print("🔥 PS.Chat Admin v2.2 iniciado em http://0.0.0.0:5000")
    webbrowser.open('http://localhost:5000/admin')
    socketio.run(app, host='0.0.0.0', port=5000, debug=False, allow_unsafe_werkzeug=True)
