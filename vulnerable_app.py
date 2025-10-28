
from flask import Flask, request, render_template_string, session, redirect, url_for
import sqlite3
import os
import hashlib
import hmac # para inyeccion sql. Usar como password: cualquiercosa' OR '1'='1 
import secrets
import time

# ---- Sanitización robusta (Bleach con fallback) ----
try:
    import bleach
    def sanitize(text: str) -> str:
        # Política: NO permitir ninguna etiqueta ni atributo (texto plano)
        return bleach.clean(
            text or "",
            tags=[],               # sin tags
            attributes={},         # sin atributos
            protocols=["http", "https"],
            strip=True,            # elimina tags en vez de escaparlas
            strip_comments=True
        )
except Exception:
    # Fallback sin dependencias: escapar todo como texto
    import html
    def sanitize(text: str) -> str:
        return html.escape(text or "", quote=True)
# ----------------------------------------------------

# (Opcional) CSP y headers con Talisman si está disponible
USE_TALISMAN = False
try:
    from flask_talisman import Talisman
    USE_TALISMAN = True
except Exception:
    USE_TALISMAN = False

app = Flask(__name__)
# En producción usa una clave fija por entorno
app.secret_key = os.urandom(24)

# ---------- DB helpers ----------
def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

# ---------- Endurecimiento de cabeceras ----------
if USE_TALISMAN:
    # Bloquea inline scripts y solo permite recursos propios
    csp = {
        'default-src': "'self'",
        'script-src': "'self'",
        'style-src': "'self'",
        'img-src': "'self' data:",
        'object-src': "'none'",
        'base-uri': "'self'",
        'frame-ancestors': "'none'",
        'form-action': "'self'",
    }
    Talisman(
        app,
        content_security_policy=csp,
        force_https=False,   # cambia a True si usas HTTPS local
        session_cookie_secure=False
    )
else:
    @app.after_request
    def set_security_headers(resp):
        resp.headers['Content-Security-Policy'] = (
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self'; "
            "img-src 'self' data:; "
            "object-src 'none'; "
            "base-uri 'self'; "
            "frame-ancestors 'none'; "
            "form-action 'self'"
        )
        resp.headers['X-Content-Type-Options'] = 'nosniff'
        resp.headers['X-Frame-Options'] = 'DENY'
        resp.headers['Referrer-Policy'] = 'same-origin'
        resp.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
        return resp
# -----------------------------------------------

# ---------- MFA helpers ----------
MFA_TTL_SECONDS = 300  # 5 minutos
MFA_MAX_ATTEMPTS = 5 # 5 intentos

def _require_auth_and_mfa():
    """Pequeña ayuda reusable en rutas protegidas."""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    # Si aún no pasó MFA, redirigir
    if not session.get('mfa_ok'):
        return redirect(url_for('mfa'))
    return None

def _start_mfa_for(user_id: int, username: str):
    """Genera un código 2FA, lo deja en sesión (hash + exp) y lo imprime en consola."""
    # Código de 6 dígitos
    code = f"{secrets.randbelow(1_000_000):06d}"
    code_hash = hashlib.sha256(code.encode()).hexdigest()
    now = int(time.time())
    session['pending_mfa'] = {
        'user_id': user_id,
        'username': username,
        'code_hash': code_hash,
        'exp': now + MFA_TTL_SECONDS,
        'attempts': 0
    }
    session['mfa_ok'] = False
    # IMPORTANTE: entregar el código por consola/terminal (logs del servidor)
    print(f"[MFA] Código para usuario '{username}' (id={user_id}): {code}  (válido por {MFA_TTL_SECONDS//60} min)" )

def _verify_mfa(submitted_code: str) -> bool:
    data = session.get('pending_mfa')
    if not data:
        return False
    # Expiración
    if int(time.time()) > int(data.get('exp', 0)):
        return False
    # Intentos
    attempts = int(data.get('attempts', 0)) + 1
    data['attempts'] = attempts
    session['pending_mfa'] = data  # persistir incremento
    if attempts > MFA_MAX_ATTEMPTS:
        return False
    submitted_hash = hashlib.sha256((submitted_code or '').encode()).hexdigest()
    return hmac.compare_digest(submitted_hash, data.get('code_hash', ''))

def _clear_mfa_state():
    session.pop('pending_mfa', None)

# ---------- Rutas ----------
@app.route('/')
def index():
    return 'Welcome to the Task Manager Application!'

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        conn = get_db_connection()
        try:
            row = conn.execute(
                "SELECT id, role, password FROM users WHERE username = ?",
                (username,)
            ).fetchone()
        finally:
            conn.close()

        if row:
            submitted_hash = hash_password(password)
            if hmac.compare_digest(row['password'], submitted_hash):
                # Paso 1 OK -> iniciar MFA
                session.clear()  # limpiar sesión previa
                session['preauth_user'] = {'id': row['id'], 'role': row['role'], 'username': username}
                _start_mfa_for(row['id'], username)
                return redirect(url_for('mfa'))
        return 'Invalid credentials!'

    return '''
        <form method="post" autocomplete="off">
            <label>Username: <input type="text" name="username" required></label><br>
            <label>Password: <input type="password" name="password" required></label><br>
            <input type="submit" value="Login">
        </form>
    '''

@app.route('/mfa', methods=['GET', 'POST'])
def mfa():
    # Si ya autenticó MFA, ir al dashboard
    if session.get('mfa_ok') and session.get('user_id'):
        return redirect(url_for('dashboard'))

    # Debe existir un preauth válido
    pre = session.get('preauth_user')
    pending = session.get('pending_mfa')
    if not pre or not pending:
        return redirect(url_for('login'))

    error_msg = ''
    locked = False

    if request.method == 'POST':
        code = request.form.get('code', '').strip()
        # Validar intentos/expiración antes de comparar
        if int(time.time()) > int(pending.get('exp', 0)):
            error_msg = 'El código ha expirado. Inicia sesión nuevamente.'
            session.clear()
            return render_template_string(MFA_TEMPLATE, error_msg=error_msg)

        if int(pending.get('attempts', 0)) >= MFA_MAX_ATTEMPTS:
            locked = True
        else:
            if _verify_mfa(code):
                # MFA OK -> promover a sesión autenticada
                session['user_id'] = pre['id']
                session['role'] = pre['role']
                session['mfa_ok'] = True
                # limpiar datos temporales
                session.pop('preauth_user', None)
                _clear_mfa_state()
                return redirect(url_for('dashboard'))
            else:
                error_msg = 'Código incorrecto.'
                # actualizar pending para reflejar los intentos
                pending = session.get('pending_mfa', {})
                if int(pending.get('attempts', 0)) >= MFA_MAX_ATTEMPTS:
                    locked = True

    return render_template_string(MFA_TEMPLATE, error_msg=error_msg, locked=locked)

MFA_TEMPLATE = '''
{% autoescape true %}
<h1>Verificación en dos pasos</h1>
<p>Hemos enviado un código de verificación a la <strong>consola del servidor</strong>. Ingresa el código para continuar.</p>
{% if error_msg %}<p style="color:red">{{ error_msg }}</p>{% endif %}
{% if locked %}
  <p style="color:red">Demasiados intentos fallidos. Vuelve a iniciar sesión.</p>
  <a href="{{ url_for('login') }}">Volver al login</a>
{% else %}
  <form method="post" autocomplete="off">
      <label>Código MFA: <input type="text" name="code" inputmode="numeric" pattern="\d{6}" maxlength="6" required></label><br>
      <input type="submit" value="Verificar">
  </form>
  <p><small>El código expira en 5 minutos.</small></p>
{% endif %}
{% endautoescape %}
'''

@app.route('/dashboard')
def dashboard():
    redir = _require_auth_and_mfa()
    if redir:
        return redir

    user_id = session['user_id']
    conn = get_db_connection()
    try:
        tasks = conn.execute(
            "SELECT * FROM tasks WHERE user_id = ?",
            (user_id,)
        ).fetchall()
    finally:
        conn.close()

    # Nota: renderizamos como texto (autoescape ON). Ya sanitizamos al guardar.
    template = '''
        {% autoescape true %}
        <h1>Welcome, user {{ user_id }}!</h1>
        <form action="{{ url_for('add_task') }}" method="post" autocomplete="off">
            <input type="text" name="task" placeholder="New task" maxlength="500" required><br>
            <input type="submit" value="Add Task">
        </form>
        <h2>Your Tasks</h2>
        <ul>
        {% for task in tasks %}
            <li>
                {{ task['task'] }}
                <a href="{{ url_for('delete_task', task_id=task['id']) }}">Delete</a>
            </li>
        {% endfor %}
        </ul>
        {% endautoescape %}
    '''
    return render_template_string(template, user_id=user_id, tasks=tasks)

@app.route('/add_task', methods=['POST'])
def add_task():
    redir = _require_auth_and_mfa()
    if redir:
        return redir

    raw_task = request.form.get('task', '')
    # Sanitizamos EN LA ENTRADA para prevenir XSS almacenado
    clean_task = sanitize(raw_task).strip()
    if not clean_task:
        return redirect(url_for('dashboard'))
    if len(clean_task) > 500:
        clean_task = clean_task[:500]

    user_id = session['user_id']

    conn = get_db_connection()
    try:
        conn.execute(
            "INSERT INTO tasks (user_id, task) VALUES (?, ?)",
            (user_id, clean_task)
        )
        conn.commit()
    finally:
        conn.close()

    return redirect(url_for('dashboard'))

@app.route('/delete_task/<int:task_id>')
def delete_task(task_id):
    redir = _require_auth_and_mfa()
    if redir:
        return redir

    conn = get_db_connection()
    try:
        conn.execute("DELETE FROM tasks WHERE id = ?", (task_id,))
        conn.commit()
    finally:
        conn.close()

    return redirect(url_for('dashboard'))

@app.route('/admin')
def admin():
    redir = _require_auth_and_mfa()
    if redir:
        return redir

    if session.get('role') != 'admin':
        return redirect(url_for('dashboard'))

    return 'Welcome to the admin panel!'

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    # En producción, desactiva debug
    app.run(debug=True)