import pytest
from app import db
from models import User, Parcel, Destination
from flask_jwt_extended import create_access_token

def test_create_parcel(test_client, init_database):
    user = User(email='user@example.com', password='password123')
    db.session.add(user)
    db.session.commit()

    access_token = create_access_token(identity={'id': user.id})

    response = test_client.post('/parcels', json={
        'parcel_item': 'Book',
        'parcel_description': 'A book about testing',
        'parcel_weight': 1.0,
        'parcel_cost': 10.0,
        'destination_id': 1
    }, headers={'Authorization': f'Bearer {access_token}'})
    assert response.status_code == 201
    assert response.json['message'] == 'Parcel created successfully'

def test_get_parcel(test_client, init_database):
    parcel = Parcel(
        parcel_item='Book',
        parcel_description='A book about testing',
        parcel_weight=1.0,
        parcel_cost=10.0,
        parcel_status='Pending',
        user_id=1,
        destination_id=1
    )
    db.session.add(parcel)
    db.session.commit()

    response = test_client.get(f'/parcels/{parcel.id}')
    assert response.status_code == 200
    assert response.json['parcel_item'] == 'Book'

def test_update_parcel(test_client, init_database):
    parcel = Parcel(
        parcel_item='Book',
        parcel_description='A book about testing',
        parcel_weight=1.0,
        parcel_cost=10.0,
        parcel_status='Pending',
        user_id=1,
        destination_id=1
    )
    db.session.add(parcel)
    db.session.commit()

    access_token = create_access_token(identity={'id': 1})

    response = test_client.put(f'/parcels/{parcel.id}', json={
        'parcel_item': 'Updated Book',
        'parcel_cost': 15.0
    }, headers={'Authorization': f'Bearer {access_token}'})
    assert response.status_code == 200
    assert response.json['message'] == 'Parcel updated successfully'

def test_delete_parcel(test_client, init_database):
    parcel = Parcel(
        parcel_item='Book',
        parcel_description='A book about testing',
        parcel_weight=1.0,
        parcel_cost=10.0,
        parcel_status='Pending',
        user_id=1,
        destination_id=1
    )
    db.session.add(parcel)
    db.session.commit()

    access_token = create_access_token(identity={'id': 1})

    response = test_client.delete(f'/parcels/{parcel.id}', headers={'Authorization': f'Bearer {access_token}'})
    assert response.status_code == 200
    assert response.json['message'] == 'Parcel deleted successfully'
