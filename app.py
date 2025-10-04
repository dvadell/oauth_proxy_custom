from flask import (
    Flask,
    g,
    jsonify,
    render_template,
    request,
    redirect,
    session,
    url_for,
)
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import os
import click
from datetime import datetime, timedelta
from functools import wraps
from urllib.parse import urlparse, urljoin
from flask_wtf.csrf import CSRFProtect

# In your Flask app initialization
SECRET_KEY = os.environ.get("SECRET_KEY")
if not SECRET_KEY:
    raise ValueError(
        "No SECRET_KEY set for Flask application. Please set it as an environment variable for production."
    )

app = Flask(__name__)
app.secret_key = SECRET_KEY
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=24)
csrf = CSRFProtect(app)

# Get the directory where this script is located
APP_ROOT = os.path.dirname(os.path.abspath(__file__))
# Define the default database path relative to the app root
DEFAULT_DB_PATH = os.path.join(APP_ROOT, "data", "users.db")
DATABASE = os.environ.get("DATABASE_PATH", DEFAULT_DB_PATH)


def get_db():
    """Opens a new database connection if there is none yet for the
    current application context.
    """
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(error):
    """Closes the database again at the end of the request."""
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    """Inicializar la base de datos con los 9 usuarios"""
    db = sqlite3.connect(DATABASE)
    c = db.cursor()
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password_hash TEXT NOT NULL,
            email TEXT,
            must_change_password INTEGER DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP,
            failed_attempts INTEGER DEFAULT 0,
            locked_until TIMESTAMP
        )
    """
    )

    # Crear los 9 usuarios ahid1 a ahid9 con contraseña igual al usuario
    for i in range(1, 10):
        username = f"ahid{i}"
        password_hash = hash_password(username)
        c.execute(
            """
            INSERT OR IGNORE INTO users 
            (username, password_hash, email, must_change_password)
            VALUES (?, ?, ?, 1)
        """,
            (username, password_hash, f"{username}@ardor.link"),
        )

    db.commit()
    db.close()
    print("Base de datos inicializada con 9 usuarios (ahid1-ahid9)")

@app.cli.command("init-db")
def init_db_command():
    """Clear existing data and create new tables."""
    init_db()
    click.echo("Initialized the database.")

def hash_password(password):
    """Hashear contraseña con PBKDF2"""
    return generate_password_hash(password)


def check_password_strength(password):
    """Verifica que la contraseña sea robusta"""
    if len(password) < 8:
        return False, "La contraseña debe tener al menos 8 caracteres"
    if not any(c.isupper() for c in password):
        return False, "Debe contener al menos una mayúscula"
    if not any(c.islower() for c in password):
        return False, "Debe contener al menos una minúscula"
    if not any(c.isdigit() for c in password):
        return False, "Debe contener al menos un número"
    if not any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
        return False, "Debe contener al menos un carácter especial (!@#$%...)"
    return True, "OK"


def require_auth(f):
    """Decorator para rutas que requieren autenticación"""

    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "username" not in session:
            return redirect(url_for("login", rd=request.url))
        return f(*args, **kwargs)

    return decorated_function


def is_safe_url(target):
    """Verifica si una URL es segura para redireccionar"""
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ("http", "https") and ref_url.netloc == test_url.netloc


def is_user_locked(username):
    """Verifica si el usuario está bloqueado por intentos fallidos"""
    db = get_db()
    c = db.cursor()
    c.execute("SELECT locked_until FROM users WHERE username = ?", (username,))
    result = c.fetchone()

    if result and result[0]:
        locked_until = datetime.fromisoformat(result[0])
        if datetime.now() < locked_until:
            return True, locked_until
    return False, None


def record_failed_attempt(username):
    """Registra un intento fallido de login"""
    db = get_db()
    c = db.cursor()
    c.execute("SELECT failed_attempts FROM users WHERE username = ?", (username,))
    result = c.fetchone()

    if result:
        failed_attempts = result[0] + 1
        if failed_attempts >= 5:
            # Bloquear por 15 minutos después de 5 intentos
            locked_until = datetime.now() + timedelta(minutes=15)
            c.execute(
                """
                UPDATE users 
                SET failed_attempts = ?, locked_until = ?
                WHERE username = ?
            """,
                (failed_attempts, locked_until.isoformat(), username),
            )
        else:
            c.execute(
                """
                UPDATE users 
                SET failed_attempts = ?
                WHERE username = ?
            """,
                (failed_attempts, username),
            )

    db.commit()


def reset_failed_attempts(username):
    """Resetea los intentos fallidos después de login exitoso"""
    db = get_db()
    c = db.cursor()
    c.execute(
        """
        UPDATE users 
        SET failed_attempts = 0, locked_until = NULL
        WHERE username = ?
    """,
        (username,),
    )
    db.commit()


@app.route("/")
def index():
    """Página principal - portal de usuario"""
    if "username" in session:
        return render_template("portal.html", username=session["username"])
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    """Página de login"""
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not username or not password:
            return render_template(
                "login.html", error="Usuario y contraseña son requeridos"
            )

        # Verificar si está bloqueado
        is_locked, locked_until = is_user_locked(username)
        if is_locked:
            minutes_left = int((locked_until - datetime.now()).total_seconds() / 60)
            return render_template(
                "login.html",
                error=f"Usuario bloqueado. Intenta en {minutes_left} minutos.",
            )

        db = get_db()
        c = db.cursor()
        c.execute(
            """
            SELECT password_hash, must_change_password, failed_attempts 
            FROM users WHERE username = ?
        """,
            (username,),
        )
        user = c.fetchone()

        if user and check_password_hash(user[0], password):
            # Login exitoso
            session.permanent = True
            session["username"] = username
            session["authenticated"] = True

            # Resetear intentos fallidos
            reset_failed_attempts(username)

            # Actualizar último login
            c.execute(
                "UPDATE users SET last_login = ? WHERE username = ?",
                (datetime.now().isoformat(), username),
            )
            db.commit()

            # Si debe cambiar contraseña (primer login)
            if user[1] == 1:
                return redirect(
                    url_for("force_change_password", rd=request.args.get("rd", "/"))
                )

            # Redirigir a donde venía o al portal
            redirect_url = request.args.get("rd")
            if not redirect_url or not is_safe_url(redirect_url):
                redirect_url = url_for("index")
            return redirect(redirect_url)
        else:
            # Login fallido
            if user:  # Usuario existe pero contraseña incorrecta
                record_failed_attempt(username)
            return render_template(
                "login.html", error="Usuario o contraseña incorrectos"
            )

    # GET request
    return render_template("login.html")


@app.route("/force-change-password", methods=["GET", "POST"])
@require_auth
def force_change_password():
    """Forzar cambio de contraseña en primer login"""
    if request.method == "POST":
        current_password = request.form.get("current_password", "")
        new_password = request.form.get("new_password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not all([current_password, new_password, confirm_password]):
            return render_template(
                "first_login.html", error="Todos los campos son requeridos"
            )

        if new_password != confirm_password:
            return render_template(
                "first_login.html", error="Las contraseñas nuevas no coinciden"
            )

        # Verificar robustez
        is_strong, message = check_password_strength(new_password)
        if not is_strong:
            return render_template("first_login.html", error=message)

        # Verificar contraseña actual
        db = get_db()
        c = db.cursor()
        c.execute(
            "SELECT password_hash FROM users WHERE username = ?", (session["username"],)
        )
        user = c.fetchone()

        if user and check_password_hash(user[0], current_password):
            # Actualizar contraseña
            new_hash = hash_password(new_password)
            c.execute(
                """
                UPDATE users 
                SET password_hash = ?, must_change_password = 0 
                WHERE username = ?
            """,
                (new_hash, session["username"]),
            )
            db.commit()

            redirect_url = request.args.get("rd")
            if not redirect_url or not is_safe_url(redirect_url):
                redirect_url = url_for("index")
            return redirect(redirect_url)
        else:
            return render_template(
                "first_login.html", error="Contraseña actual incorrecta"
            )

    return render_template("first_login.html")


@app.route("/change-password", methods=["GET", "POST"])
@require_auth
def change_password():
    """Cambiar contraseña cuando el usuario quiera"""
    if request.method == "POST":
        current_password = request.form.get("current_password", "")
        new_password = request.form.get("new_password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not all([current_password, new_password, confirm_password]):
            return render_template(
                "change_change.html", error="Todos los campos son requeridos"
            )

        if new_password != confirm_password:
            return render_template(
                "change_password.html", error="Las contraseñas nuevas no coinciden"
            )

        is_strong, message = check_password_strength(new_password)
        if not is_strong:
            return render_template("change_password.html", error=message)

        db = get_db()
        c = db.cursor()
        c.execute(
            "SELECT password_hash FROM users WHERE username = ?", (session["username"],)
        )
        user = c.fetchone()

        if user and check_password_hash(user[0], current_password):
            new_hash = hash_password(new_password)
            c.execute(
                "UPDATE users SET password_hash = ? WHERE username = ?",
                (new_hash, session["username"]),
            )
            db.commit()
            return render_template(
                "change_password.html", success="Contraseña cambiada exitosamente"
            )
        else:
            return render_template(
                "change_password.html", error="Contraseña actual incorrecta"
            )

    return render_template("change_password.html")


@app.route("/auth/validate")
def auth_validate():
    """Endpoint para nginx auth_request - valida si el usuario está autenticado"""
    if session.get("authenticated"):
        username = session.get("username", "")

        # Verificar que no necesite cambiar contraseña
        db = get_db()
        c = db.cursor()
        c.execute(
            "SELECT must_change_password, email FROM users WHERE username = ?",
            (username,),
        )
        user = c.fetchone()

        if user and user[0] == 1:
            # Debe cambiar contraseña, no autorizar
            return "", 401

        email = user[1] if user else f"{username}@ardor.link"

        # Retornar headers para nginx
        response = app.make_response(("", 200))
        response.headers["X-Auth-Request-User"] = username
        response.headers["X-Auth-Request-Email"] = email
        return response

    return "", 401


@app.route("/oauth/validate")
def oauth_validate():
    """Alias para compatibilidad"""
    return auth_validate()


@app.route("/oauth/token", methods=["POST"])
def oauth_token():
    """Endpoint dummy para OAuth2 Proxy"""
    return jsonify({"access_token": "dummy", "token_type": "Bearer"})


@app.route("/oauth/userinfo")
def oauth_userinfo():
    """Endpoint para información del usuario"""
    if session.get("authenticated"):
        username = session.get("username", "")
        db = get_db()
        c = db.cursor()
        c.execute("SELECT email FROM users WHERE username = ?", (username,))
        user = c.fetchone()

        email = user[0] if user else f"{username}@ardor.link"
        return jsonify({"sub": username, "email": email, "name": username})
    return jsonify({"error": "unauthorized"}), 401


@app.route("/logout")
def logout():
    """Cerrar sesión"""
    session.clear()
    return redirect(url_for("login"))


if __name__ == "__main__":
    # Crear directorio de datos si no existe
    os.makedirs(os.path.dirname(DATABASE), exist_ok=True)

    # Ejecutar app
    app.run(host="0.0.0.0", port=5000, debug=False)