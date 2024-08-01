from flask import Flask, jsonify, request, make_response
from flask_restful import Api, Resource
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import hmac

# Define a safe string comparison function
def safe_str_cmp(a, b):
    return hmac.compare_digest(a, b)

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///sendit.db'  # Ensure this path is correct
app.config['SECRET_KEY'] = 'your_secret_key'  # Update as needed

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)
api = Api(app)

# Import models after initializing db
from server.models import User, Admin, Parcel, Destination

# Define a simple home route
@app.route('/')
def home():
    return jsonify({'message': 'Welcome to the SendIT API!'}), 200

# Define resources for Users
class Users(Resource):
    def get(self, user_id):
        user = User.query.get(user_id)
        if user:
            return make_response(jsonify(user.to_dict()), 200)
        return jsonify({'message': 'User not found'}), 404
    
    def patch(self, user_id):
        data = request.get_json()
        user = User.query.get(user_id)
        if user:
            if 'email' in data:
                user.email = data['email']
            if 'password' in data:
                user.password_hash = bcrypt.generate_password_hash(data['password']).decode('utf-8')
            db.session.commit()
            return make_response(jsonify(user.to_dict()), 200)
        return jsonify({'message': 'User not found'}), 404
    
    def delete(self, user_id):
        user = User.query.get(user_id)
        if user:
            db.session.delete(user)
            db.session.commit()
            return '', 204
        return jsonify({'message': 'User not found'}), 404

class UserList(Resource):
    def get(self):
        users = [user.to_dict() for user in User.query.all()]
        return make_response(jsonify(users), 200)
    
    def post(self):
        data = request.get_json()
        if not data or 'email' not in data or 'password' not in data:
            return {'error': 'Missing data'}, 400
        try:
            hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
            user = User(
                email=data['email'],
                password_hash=hashed_password
            )
            db.session.add(user)
            db.session.commit()
            return make_response(jsonify(user.to_dict()), 201)
        except Exception as e:
            db.session.rollback()
            return {'error': str(e)}, 400

api.add_resource(UserList, '/users')
api.add_resource(Users, '/users/<int:user_id>')

# Define routes for Parcels
@app.route('/parcels', methods=['POST'])
@jwt_required()
def create_parcel():
    data = request.get_json()
    if not data or not all(k in data for k in ('parcel_item', 'parcel_weight', 'destination_id')):
        return jsonify({'message': 'Missing parcel information'}), 400

    current_user = get_jwt_identity()
    new_parcel = Parcel(
        parcel_item=data.get('parcel_item'),
        parcel_description=data.get('parcel_description', ''),
        parcel_weight=data.get('parcel_weight'),
        parcel_cost=data.get('parcel_cost', 0),
        parcel_status='Pending',
        user_id=current_user['id'],
        destination_id=data.get('destination_id')
    )
    db.session.add(new_parcel)
    db.session.commit()
    return jsonify({'message': 'Parcel created successfully'}), 201

@app.route('/parcels/<int:parcel_id>', methods=['GET'])
@jwt_required()
def get_parcel(parcel_id):
    parcel = Parcel.query.get_or_404(parcel_id)
    return jsonify({
        'id': parcel.id,
        'parcel_item': parcel.parcel_item,
        'parcel_description': parcel.parcel_description,
        'parcel_weight': parcel.parcel_weight,
        'parcel_cost': parcel.parcel_cost,
        'parcel_status': parcel.parcel_status,
        'user_id': parcel.user_id,
        'destination_id': parcel.destination_id
    }), 200

@app.route('/parcels/<int:parcel_id>', methods=['PUT'])
@jwt_required()
def update_parcel(parcel_id):
    data = request.get_json()
    parcel = Parcel.query.get_or_404(parcel_id)
    current_user = get_jwt_identity()

    if parcel.user_id != current_user['id']:
        return jsonify({'message': 'Unauthorized'}), 403

    if 'parcel_item' in data:
        parcel.parcel_item = data['parcel_item']
    if 'parcel_description' in data:
        parcel.parcel_description = data['parcel_description']
    if 'parcel_weight' in data:
        parcel.parcel_weight = data['parcel_weight']
    if 'parcel_cost' in data:
        parcel.parcel_cost = data['parcel_cost']
    if 'destination_id' in data:
        parcel.destination_id = data['destination_id']
    if 'parcel_status' in data:
        parcel.parcel_status = data['parcel_status']

    db.session.commit()
    return jsonify({'message': 'Parcel updated successfully'}), 200

@app.route('/parcels/<int:parcel_id>', methods=['DELETE'])
@jwt_required()
def delete_parcel(parcel_id):
    parcel = Parcel.query.get_or_404(parcel_id)
    current_user = get_jwt_identity()

    if parcel.user_id != current_user['id']:
        return jsonify({'message': 'Unauthorized'}), 403

    db.session.delete(parcel)
    db.session.commit()
    return jsonify({'message': 'Parcel deleted successfully'}), 200

# Define routes for Admins
@app.route('/admin/register', methods=['POST'])
def admin_register():
    data = request.get_json()
    if not data or 'email' not in data or 'password' not in data or 'first_name' not in data or 'last_name' not in data:
        return jsonify({'message': 'Missing data'}), 400
    if Admin.query.filter_by(email=data['email']).first():
        return jsonify({'message': 'Admin already exists'}), 400
    hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
    new_admin = Admin(
        first_name=data['first_name'],
        last_name=data['last_name'],
        email=data['email'],
        password_hash=hashed_password
    )
    db.session.add(new_admin)
    db.session.commit()
    return jsonify({'message': 'Admin created successfully'}), 201

@app.route('/admin/login', methods=['POST'])
def admin_login():
    data = request.get_json()
    admin = Admin.query.filter_by(email=data['email']).first()

    if admin and bcrypt.check_password_hash(admin.password_hash, data['password']):
        access_token = create_access_token(identity=admin.id)
        return jsonify({'access_token': access_token}), 200
    return jsonify({'message': 'Invalid credentials'}), 401

@app.route('/admin/parcels/<int:parcel_id>/status', methods=['PUT'])
@jwt_required()
def admin_change_status(parcel_id):
    data = request.get_json()
    current_user_id = get_jwt_identity()
    admin = Admin.query.get(current_user_id)
    if not admin:
        return jsonify({'message': 'You are not an admin'}), 403
    
    parcel = Parcel.query.get_or_404(parcel_id)
    if 'parcel_status' not in data:
        return jsonify({'message': 'No status provided'}), 400
    parcel.parcel_status = data['parcel_status']
    db.session.commit()
    return jsonify({'message': 'Status updated successfully'}), 200

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Ensure all tables are created
    app.run(debug=True)
