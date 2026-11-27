"""
Tests for the /api/auth/reset-password endpoint (CWE-287: Improper Authentication).
The endpoint must require authentication and only allow users to reset their own
password (admins may reset any account).
"""
from models import User, db

URL = '/api/auth/reset-password'


def _make_user(username, email, password='originalpass1'):
    user = User(username=username, email=email, role='team_member')
    user.set_password(password)
    db.session.add(user)
    db.session.commit()
    return user


def test_unauthenticated_reset_is_rejected(client, sample_user):
    """An anonymous caller must not be able to reset any password"""
    response = client.post(URL, json={
        'email': sample_user.email,
        'new_password': 'attackerpass1',
    })
    assert response.status_code == 401

    db.session.refresh(sample_user)
    assert sample_user.check_password('password123')
    assert not sample_user.check_password('attackerpass1')


def test_invalid_token_reset_is_rejected(client, sample_user):
    """A forged/invalid token is not authentication"""
    response = client.post(
        URL,
        json={'email': sample_user.email, 'new_password': 'attackerpass1'},
        headers={'Authorization': 'Bearer not-a-valid-token'},
    )
    assert response.status_code == 401

    db.session.refresh(sample_user)
    assert sample_user.check_password('password123')


def test_user_can_reset_own_password(client, sample_user, auth_headers):
    """An authenticated user can change their own password"""
    response = client.post(
        URL,
        json={'email': sample_user.email, 'new_password': 'newpass456'},
        headers=auth_headers,
    )
    assert response.status_code == 200

    db.session.refresh(sample_user)
    assert sample_user.check_password('newpass456')


def test_user_cannot_reset_other_users_password(client, sample_user, auth_headers):
    """An authenticated non-admin must not reset someone else's password"""
    victim = _make_user('victim', 'victim@example.com')

    response = client.post(
        URL,
        json={'email': victim.email, 'new_password': 'attackerpass1'},
        headers=auth_headers,
    )
    assert response.status_code == 404

    db.session.refresh(victim)
    assert victim.check_password('originalpass1')
    assert not victim.check_password('attackerpass1')


def test_admin_can_reset_other_users_password(client, admin_auth_headers, sample_user):
    """Admins may reset any user's password"""
    response = client.post(
        URL,
        json={'email': sample_user.email, 'new_password': 'adminset789'},
        headers=admin_auth_headers,
    )
    assert response.status_code == 200

    db.session.refresh(sample_user)
    assert sample_user.check_password('adminset789')


def test_missing_fields_rejected(client, auth_headers):
    """Authenticated requests still require email and new password"""
    response = client.post(URL, json={'email': 'test@example.com'}, headers=auth_headers)
    assert response.status_code == 400
