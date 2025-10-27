from flask import Flask, request, render_template_string, session, redirect, url_for
import sqlite3
import os
import hashlib
import hmac # para inyeccion sql. Usar como password: cualquiercosa' OR '1'='1 

app = Flask(__name__)
app.secret_key = os.urandom(24)


def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn


def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


@app.route('/')
def index():
    return 'Welcome to the Task Manager Application!'


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')

        # 1) Nunca interpolar variables en la SQL.
        # 2) Buscar por username y comparar hashes en la app.
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
            # Comparación en tiempo constante para evitar micro-filtraciones de timing
            if hmac.compare_digest(row['password'], submitted_hash):
                session['user_id'] = row['id']
                session['role'] = row['role']
                return redirect(url_for('dashboard'))

        # Mensaje genérico para no filtrar si falló username o password
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

    return render_template_string('''
        <h1>Welcome, user {{ user_id }}!</h1>
        <form action="/add_task" method="post">
            <input type="text" name="task" placeholder="New task"><br>
            <input type="submit" value="Add Task">
        </form>
        <h2>Your Tasks</h2>
        <ul>
        {% for task in tasks %}
            <li>{{ task['task'] }} <a href="/delete_task/{{ task['id'] }}">Delete</a></li>
        {% endfor %}
        </ul>
    ''', user_id=user_id, tasks=tasks)


@app.route('/add_task', methods=['POST'])
def add_task():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    task = request.form['task']
    user_id = session['user_id']

    conn = get_db_connection()
    try:
        conn.execute(
            "INSERT INTO tasks (user_id, task) VALUES (?, ?)",
            (user_id, task)
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
    app.run(debug=True)
