import pytest
from flask import session

def test_index_logged_out(client):
    """Test that the index page redirects to login when logged out."""
    response = client.get('/')
    assert response.status_code == 302
    assert '/login' in response.headers['Location']

def test_login_page(client):
    """Test that the login page loads."""
    response = client.get('/login')
    assert response.status_code == 200
    assert b'Iniciar Sesi' in response.data # Iniciar Sesión

def test_login_success(client):
    """Test a successful login."""
    response = client.post('/login', data={
        'username': 'ahid1',
        'password': 'ahid1'
    }, follow_redirects=True)
    assert response.status_code == 200
    # After first login, it should force a password change
    assert b'Cambio de Contrase' in response.data # Cambio de Contraseña Requerido

    # Check that the session is set
    with client.session_transaction() as sess:
        assert sess['authenticated'] is True
        assert sess['username'] == 'ahid1'

def test_login_wrong_password(client):
    """Test a login with a wrong password."""
    response = client.post('/login', data={
        'username': 'ahid1',
        'password': 'wrongpassword'
    }, follow_redirects=True)
    assert response.status_code == 200
    assert b'Usuario o contrase' in response.data # Usuario o contraseña incorrectos

def test_index_logged_in(client):
    """Test the index page when logged in."""
    # First, log in
    client.post('/login', data={'username': 'ahid2', 'password': 'ahid2'})
    
    # Now, access the index page
    response = client.get('/')
    assert response.status_code == 200
    assert b'Portal de Usuario' in response.data

def test_brute_force_lockout(client):
    """Test that 6 failed login attempts lock the account."""
    # Attempts 1-4 should show incorrect password
    for i in range(4):
        res = client.post('/login', data={'username': 'ahid3', 'password': 'wrong'})
        assert b'Usuario o contrase' in res.data
        assert b'Usuario bloqueado' not in res.data

    # The 5th attempt records the final failure and locks the account
    res = client.post('/login', data={'username': 'ahid3', 'password': 'wrong'})
    assert b'Usuario o contrase' in res.data
    assert b'Usuario bloqueado' not in res.data

    # The 6th attempt should find the user is locked
    res = client.post('/login', data={'username': 'ahid3', 'password': 'wrong'})
    assert b'Usuario bloqueado' in res.data

    # A correct login should also fail now
    res = client.post('/login', data={'username': 'ahid3', 'password': 'ahid3'})
    assert b'Usuario bloqueado' in res.data

def test_auth_validate_logged_out(client):
    """Test the /auth/validate endpoint when logged out."""
    response = client.get('/auth/validate')
    assert response.status_code == 401

def test_auth_validate_logged_in_must_change_password(client):
    """Test /auth/validate when user must change password."""
    client.post('/login', data={'username': 'ahid4', 'password': 'ahid4'})
    response = client.get('/auth/validate')
    assert response.status_code == 401 # Should be unauthorized

def test_auth_validate_logged_in_success(client):
    """Test a successful /auth/validate call."""
    # Log in
    client.post('/login', data={'username': 'ahid5', 'password': 'ahid5'})
    
    # Manually change password to pass the check
    with client.session_transaction() as sess:
        username = sess['username']
    
    from app import DATABASE
    import sqlite3
    conn = sqlite3.connect(DATABASE)
    conn.execute("UPDATE users SET must_change_password = 0 WHERE username = ?", (username,))
    conn.commit()
    conn.close()

    response = client.get('/auth/validate')
    assert response.status_code == 200
    assert response.headers['X-Auth-Request-User'] == 'ahid5'
    assert response.headers['X-Auth-Request-Email'] == 'ahid5@ardor.link'
