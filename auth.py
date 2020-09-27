from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import uuid
import datetime
from functools import wraps

app = Flask(__name__)

app.config['SECRET_KEY'] = 'thisissecret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'

db = SQLAlchemy(app)


class AuthorizedUser(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    name = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(80))
    ip_address = db.Column(db.String(50))
    admin = db.Column(db.Boolean)

    def get_user_data(self):
        return {'public_id': self.public_id, 'name': self.name, 'password': self.password,
                'ip_address': self.ip_address, 'admin': self.admin}


def add_admin_account(name, password, ip_address):
    hashed_password = generate_password_hash(password, method='sha256')

    new_user = AuthorizedUser(public_id=str(uuid.uuid4()), ip_address=ip_address, name=name,
                              password=hashed_password, admin=True)
    db.session.add(new_user)
    db.session.commit()


def token_required(func):
    @wraps(func)
    def decorated(*args, **kwargs):
        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return jsonify({'message': 'Token is missing from x-access-token header!'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = AuthorizedUser.query.filter_by(public_id=data['public_id']).first()
        except:
            return jsonify({'message': 'Token is invalid!'}), 401

        return func(current_user, *args, **kwargs)

    return decorated


@app.route('/user', methods=['GET'])
@token_required
def get_all_users(current_user):
    if not current_user.admin:
        return jsonify({'message': 'Cannot perform that function!'})

    users = AuthorizedUser.query.all()

    output = []

    for user in users:
        output.append(user.get_user_data())

    return jsonify({'users': output})


@app.route('/user/<public_id>', methods=['GET'])
@token_required
def get_one_user(current_user, public_id):
    if not current_user.admin:
        return jsonify({'message': 'Cannot perform that function!'})

    user = AuthorizedUser.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'message': 'No user found!'})

    return jsonify({'user': user.get_user_data()})


@app.route('/user', methods=['POST'])
@token_required
def create_user(current_user):
    if not current_user.admin:
        return jsonify({'message': 'Cannot perform that function!'})

    try:
        data = request.get_json()
        hashed_password = generate_password_hash(data['password'], method='sha256')

        new_user = AuthorizedUser(public_id=str(uuid.uuid4()), ip_address=str(request.remote_addr), name=data['name'],
                                  password=hashed_password, admin=False)
        db.session.add(new_user)
        db.session.commit()

        return jsonify({'message': 'New user created!'})
    except:
        return jsonify({'message': 'Could not create new user. Verify that required data is passed.'})


@app.route('/user/<public_id>', methods=['PUT'])
@token_required
def promote_user(current_user, public_id):
    if not current_user.admin:
        return jsonify({'message': 'Cannot perform that function!'})

    user = AuthorizedUser.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'message': 'No user found!'})

    user.admin = True
    db.session.commit()

    return jsonify({'message': 'The user has been promoted!'})


@app.route('/user/<public_id>', methods=['DELETE'])
@token_required
def delete_user(current_user, public_id):
    if not current_user.admin:
        return jsonify({'message': 'Cannot perform that function!'})

    user = AuthorizedUser.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'message': 'No user found!'})

    db.session.delete(user)
    db.session.commit()

    return jsonify({'message': 'The user has been deleted!'})


@app.route('/login', methods=['GET'])
def login():
    auth = request.authorization
    if not auth or not auth.username or not auth.password:
        return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})

    user = AuthorizedUser.query.filter_by(name=auth.username).first()

    if not user:
        return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})

    if check_password_hash(user.password, auth.password):
        if str(request.remote_addr) != user.ip_address:
            return make_response('Unauthorized IP Address', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})
        token = jwt.encode(
            {'public_id': user.public_id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)},
            app.config['SECRET_KEY'])
        data = user.get_user_data()
        data['token'] = token.decode('UTF-8')
        return data

    return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})


if __name__ == '__main__':
    # db.create_all()
    # add_admin_account('Admin', 'Admin100!', '127.0.0.1')
    app.run(debug=True)
