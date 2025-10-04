import os
from app import get_db, hash_password


def test_index_logged_out(client):
    """Test that the index page redirects to login when logged out."""
    response = client.get("/")
    assert response.status_code == 302
    assert "/login" in response.headers["Location"]


def test_login_page(client):
    """Test that the login page loads."""
    response = client.get("/login")
    assert response.status_code == 200
    assert b"Iniciar Sesi" in response.data  # Iniciar Sesión


def test_login_success(client):
    """Test a successful login."""
    response = client.post(
        "/login", data={"username": "ahid1", "password": "ahid1"}, follow_redirects=True
    )
    assert response.status_code == 200
    # After first login, it should force a password change
    assert b"Cambio de Contrase" in response.data  # Cambio de Contraseña Requerido

    # Check that the session is set
    with client.session_transaction() as sess:
        assert sess["authenticated"] is True
        assert sess["username"] == "ahid1"


def test_login_wrong_password(client):
    """Test a login with a wrong password."""
    response = client.post(
        "/login",
        data={"username": "ahid1", "password": "wrongpassword"},
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert b"Usuario o contrase" in response.data  # Usuario o contraseña incorrectos


def test_index_logged_in(client):
    """Test the index page when logged in."""
    # First, log in
    client.post("/login", data={"username": "ahid2", "password": "ahid2"})

    # Now, access the index page
    response = client.get("/")
    assert response.status_code == 200
    assert b"Portal de Usuario" in response.data


def test_brute_force_lockout(client):
    """Test that 6 failed login attempts lock the account."""
    for i in range(4):
        res = client.post("/login", data={"username": "ahid3", "password": "wrong"})
        assert b"Usuario o contrase" in res.data
        assert b"Usuario bloqueado" not in res.data

    res = client.post("/login", data={"username": "ahid3", "password": "wrong"})
    assert b"Usuario o contrase" in res.data
    assert b"Usuario bloqueado" not in res.data

    res = client.post("/login", data={"username": "ahid3", "password": "wrong"})
    assert b"Usuario bloqueado" in res.data

    res = client.post("/login", data={"username": "ahid3", "password": "ahid3"})
    assert b"Usuario bloqueado" in res.data


def test_auth_validate_logged_out(client):
    """Test the /auth/validate endpoint when logged out."""
    response = client.get("/auth/validate")
    assert response.status_code == 401


def test_auth_validate_logged_in_must_change_password(client):
    """Test /auth/validate when user must change password."""
    client.post("/login", data={"username": "ahid4", "password": "ahid4"})
    response = client.get("/auth/validate")
    assert response.status_code == 401


def test_auth_validate_logged_in_success(client):
    """Test a successful /auth/validate call."""
    db = get_db()
    c = db.cursor()
    username = "ahid5_no_force_change"
    password = "ahid5_password"
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

    client.post("/login", data={"username": username, "password": password})

    response = client.get("/auth/validate")
    assert response.status_code == 200
    assert response.headers["X-Auth-Request-User"] == username
    assert response.headers["X-Auth-Request-Email"] == f"{username}@ardor.link"


def test_login_redirect_rd_parameter(client):
    """Test that login redirects to the 'rd' parameter if safe and provided."""
    os.environ["ALLOWED_REDIRECT_DOMAIN"] = "ardor.link"
    db = get_db()
    c = db.cursor()
    username = "testuser_rd"
    password = "testpassword_rd"
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

    redirect_target = "https://test.of.ardor.link/some/path"
    response = client.post(
        f"/login?rd={redirect_target}",
        data={"username": username, "password": password},
        headers={"Host": "auth.of.ardor.link"},
        follow_redirects=False,
    )
    assert response.status_code == 302
    assert response.headers["Location"] == redirect_target


def test_session_persistence_after_login(client):
    """Test that the session persists after a successful login."""
    os.environ["ALLOWED_REDIRECT_DOMAIN"] = "ardor.link"

    db = get_db()
    c = db.cursor()
    username = "session_test_user"
    password = "Session_Pass_123!"
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
    client.post(
        "/login",
        data={"username": username, "password": password},
        follow_redirects=True,
    )

    # Access a protected page (e.g., the portal page)
    response = client.get("/")
    assert response.status_code == 200
    assert b"Portal de Usuario" in response.data

    # Check that the session is still active
    with client.session_transaction() as sess:
        assert sess["authenticated"] is True
        assert sess["username"] == username


def test_change_password_redirect_no_rd(client):
    """Test that change password redirects to index when no rd parameter is provided."""
    os.environ["ALLOWED_REDIRECT_DOMAIN"] = "ardor.link"

    db = get_db()
    c = db.cursor()
    username = "ahid_change_pass_no_rd"
    old_password = "old_pass_123"
    new_password = "New_Pass_456!"
    password_hash = hash_password(old_password)
    c.execute(
        """
        INSERT OR IGNORE INTO users
        (username, password_hash, email, must_change_password)
        VALUES (?, ?, ?, 0)
        """,
        (username, password_hash, f"{username}@ardor.link"),
    )
    db.commit()

    client.post(
        "/login",
        data={"username": username, "password": old_password},
        follow_redirects=True,
    )

    # Access a protected page to ensure session is active
    client.get("/")

    response = client.post(
        "/change-password",
        data={
            "current_password": old_password,
            "new_password": new_password,
            "confirm_password": new_password,
        },
        follow_redirects=False,
    )
    assert response.status_code == 302
    assert response.headers["Location"] == "/"


def test_change_password_redirect_safe_rd(client):
    """Test that change password redirects to safe rd parameter."""
    os.environ["ALLOWED_REDIRECT_DOMAIN"] = "ardor.link"

    db = get_db()
    c = db.cursor()
    username = "ahid_change_pass_safe_rd"
    old_password = "old_pass_123"
    new_password = "New_Pass_456!"
    password_hash = hash_password(old_password)
    c.execute(
        """
        INSERT OR IGNORE INTO users
        (username, password_hash, email, must_change_password)
        VALUES (?, ?, ?, 0)
        """,
        (username, password_hash, f"{username}@ardor.link"),
    )
    db.commit()

    client.post(
        "/login",
        data={"username": username, "password": old_password},
        follow_redirects=True,
    )

    # Access a protected page to ensure session is active
    client.get("/")

    safe_redirect_target = "https://test.of.ardor.link/dashboard"
    response = client.post(
        f"/change-password?rd={safe_redirect_target}",
        data={
            "current_password": old_password,
            "new_password": new_password,
            "confirm_password": new_password,
        },
        follow_redirects=False,
    )
    assert response.status_code == 302
    assert response.headers["Location"] == safe_redirect_target


def test_change_password_redirect_unsafe_rd(client):
    """Test that change password redirects to index when unsafe rd parameter is provided."""
    os.environ["ALLOWED_REDIRECT_DOMAIN"] = "ardor.link"

    db = get_db()
    c = db.cursor()
    username = "ahid_change_pass_unsafe_rd"
    old_password = "old_pass_123"
    new_password = "New_Pass_456!"
    password_hash = hash_password(old_password)
    c.execute(
        """
        INSERT OR IGNORE INTO users
        (username, password_hash, email, must_change_password)
        VALUES (?, ?, ?, 0)
        """,
        (username, password_hash, f"{username}@ardor.link"),
    )
    db.commit()

    client.post(
        "/login",
        data={"username": username, "password": old_password},
        follow_redirects=True,
    )

    # Access a protected page to ensure session is active
    client.get("/")

    unsafe_redirect_target = "https://evil.com/malicious"
    response = client.post(
        f"/change-password?rd={unsafe_redirect_target}",
        data={
            "current_password": old_password,
            "new_password": new_password,
            "confirm_password": new_password,
        },
        follow_redirects=False,
    )
    assert response.status_code == 302
    assert response.headers["Location"] == "/"
