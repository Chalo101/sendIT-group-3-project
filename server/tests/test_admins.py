import pytest
from app import db
from models import Admin

def test_admin_registration(test_client, init_database):
    response = test_client.post('/admin/register', json={
        'first_name': 'Admin',
        'last_name': 'User',
        'email': 'admin@example.com',
        'password': 'adminpass'
    })
    assert response.status_code == 201
    assert response.json['message'] == 'Admin created successfully'

def test_admin_login(test_client, init_database):
    admin = Admin(first_name='Admin', last_name='User', email='admin@example.com', password='adminpass')
    db.session.add(admin)
    db.session.commit()

    response = test_client.post('/admin/login', json={
        'email': 'admin@example.com',
        'password': 'adminpass'
    })
    assert response.status_code == 200
    assert 'access_token' in response.json

def test_get_admin(test_client, init_database):
    admin = Admin(first_name='Admin', last_name='User', email='admin@example.com', password='adminpass')
    db.session.add(admin)
    db.session.commit()

    response = test_client.get(f'/admins/{admin.id}')
    assert response.status_code == 200
    assert response.json['email'] == 'admin@example.com'
