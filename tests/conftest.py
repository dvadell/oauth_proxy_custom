import pytest
import tempfile
import os

# Set a test secret key before importing the app
os.environ["SECRET_KEY"] = "test-secret-key"

from app import app as flask_app  # noqa: E402
import app as app_module  # noqa: E402
from app import get_db, hash_password


@pytest.fixture
def app():
    """Create and configure a new app instance for each test."""
    # Create a temporary file to isolate the database for each test
    db_fd, db_path = tempfile.mkstemp()

    flask_app.config.update(
        {
            "TESTING": True,
            "DATABASE": db_path,
            "WTF_CSRF_ENABLED": False,  # Disable CSRF for testing forms
            "SESSION_COOKIE_DOMAIN": None, # Disable SESSION_COOKIE_DOMAIN for testing
            "ALLOWED_REDIRECT_DOMAIN": os.environ.get("ALLOWED_REDIRECT_DOMAIN"),
        }
    )

    # Monkeypatch the DATABASE variable in the app module
    app_module.DATABASE = db_path

    # Create the database and the tables
    with flask_app.app_context():
        from app import init_db

        init_db()

    yield flask_app

    # close and remove the temporary database
    os.close(db_fd)
    os.unlink(db_path)


@pytest.fixture
def client(app):
    """A test client for the app."""
    return app.test_client()


@pytest.fixture
def logged_in_client(client):
    """A test client that is already logged in."""
    with flask_app.app_context():
        db = get_db()
        c = db.cursor()
        username = "test_logged_in_user"
        password = "Test_Password_123!"
        password_hash = hash_password(password)
        c.execute(
            """
            INSERT OR IGNORE INTO users
            (username, password_hash, email, must_change_password)
            VALUES (?, ?, ?, 0)
            """,
            (username, password_hash, f"{username}@ardor.link"),
        )
        db.commit()

    # Log in the user
    client.post("/login", data={"username": username, "password": password}, follow_redirects=True)

    return client
