import pytest
from app import db
from models import Destination

def test_create_destination(test_client, init_database):
    response = test_client.post('/destinations', json={
        'name': 'New York',
        'location': 'NY, USA'
    })
    assert response.status_code == 201
    assert response.json['message'] == 'Destination created successfully'

def test_get_destination(test_client, init_database):
    destination = Destination(name='New York', location='NY, USA')
    db.session.add(destination)
    db.session.commit()

    response = test_client.get(f'/destinations/{destination.id}')
    assert response.status_code == 200
    assert response.json['name'] == 'New York'

def test_update_destination(test_client, init_database):
    destination = Destination(name='New York', location='NY, USA')
    db.session.add(destination)
    db.session.commit()

    response = test_client.put(f'/destinations/{destination.id}', json={
        'name': 'Los Angeles',
        'location': 'CA, USA'
    })
    assert response.status_code == 200
    assert response.json['message'] == 'Destination updated successfully'

def test_delete_destination(test_client, init_database):
    destination = Destination(name='New York', location='NY, USA')
    db.session.add(destination)
    db.session.commit()

    response = test_client.delete(f'/destinations/{destination.id}')
    assert response.status_code == 200
    assert response.json['message'] == 'Destination deleted successfully'
