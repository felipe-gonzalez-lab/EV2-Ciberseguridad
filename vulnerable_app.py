from flask import Flask, request, render_template_string, session, redirect, url_for
import sqlite3
import os
import hashlib
import hmac # para inyeccion sql. Usar como password: cualquiercosa' OR '1'='1 

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

@app.route('/')
def index():
    return 'Welcome to the Task Manager Application!'

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '')
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
                session['user_id'] = row['id']
                session['role'] = row['role']
                return redirect(url_for('dashboard'))

        return 'Invalid credentials!'

    return '''
        <form method="post">
            Username: <input type="text" name="username"><br>
            Password: <input type="password" name="password"><br>
            <input type="submit" value="Login">
        </form>
    '''

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))

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
            <input type="text" name="task" placeholder="New task" maxlength="500"><br>
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
    if 'user_id' not in session:
        return redirect(url_for('login'))

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
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = get_db_connection()
    try:
        conn.execute("DELETE FROM tasks WHERE id = ?", (task_id,))
        conn.commit()
    finally:
        conn.close()

    return redirect(url_for('dashboard'))

@app.route('/admin')
def admin():
    if 'user_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('login'))

    return 'Welcome to the admin panel!'

if __name__ == '__main__':
    # En producción, desactiva debug
    app.run(debug=True)
