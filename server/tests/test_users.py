import pytest
from server.app import db
from server.models import User

def test_user_registration(test_client, init_database):
    response = test_client.post('/users', json={
        'email': 'test@example.com',
        'password': 'password123'
    })
    assert response.status_code == 201
    assert response.json['email'] == 'test@example.com'

def test_get_user(test_client, init_database):
    user = User(email='test@example.com', password='password123')
    db.session.add(user)
    db.session.commit()

    response = test_client.get(f'/users/{user.id}')
    assert response.status_code == 200
    assert response.json['email'] == 'test@example.com'

def test_update_user(test_client, init_database):
    user = User(email='test@example.com', password='password123')
    db.session.add(user)
    db.session.commit()

    response = test_client.patch(f'/users/{user.id}', json={
        'email': 'newtest@example.com'
    })
    assert response.status_code == 200
    assert response.json['email'] == 'newtest@example.com'

def test_delete_user(test_client, init_database):
    user = User(email='test@example.com', password='password123')
    db.session.add(user)
    db.session.commit()

    response = test_client.delete(f'/users/{user.id}')
    assert response.status_code == 204
