from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_restful import Api, Resource, reqparse
import re, logging, sys, bcrypt

# Set upp Flask app, API and database
app = Flask(__name__)
api = Api(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///data.db'
app.config['BUNDLE_ERRORS'] = True
db = SQLAlchemy(app)

# Define how a User is represented in the database
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)

    # Help function to convert a User object into JSON
    def user_JSON(self):
        response = {'user': {'id': self.id, 'name': self.name, 'email': self.email}}
        return response

    # Help function with verifies the given password of a user
    def verify_password(self, password):
        password = password.encode('utf-8')
        if bcrypt.checkpw(password, self.password):
            return True
        else:
            return False

    def __repr__(self):
        return f'<User {self.name}:{self.email}>'

# Help function to convert a Users object into JSON
def users_JSON(users):
        response = {'users': []}
        for user in users:
            response['users'].append({'id': user.id, 'name': user.name, 'email': user.email})
        return response

# Help function with checks whether an email is already taken
def email_taken(email):
    user_query = User.query.filter_by(email=email).first()
    if user_query is None:
        return False
    else:
        return True

def hash_password(password):
    password = password.encode('utf-8')
    hashed_password = bcrypt.hashpw(password, bcrypt.gensalt(10))
    return hashed_password

# API class that handles all users
class UsersAPI(Resource):
    def __init__(self):
        # Arguments required to be sent in the body of a POST to /api/users
        self.post_args = reqparse.RequestParser()
        self.post_args.add_argument("name", type=str, help="Name of user is required.", required=True)
        self.post_args.add_argument("email", type=str, help="User email is required.", required=True)
        self.post_args.add_argument("password", type=str, help="Account password is required.", required=True)

    # Returns information about all users in the database, in JSON format
    def get(self):
        users = User.query.all()
        return users_JSON(users)

    # Adds a new user, if the email is not already taken
    def post(self):
        args = self.post_args.parse_args()
        if email_taken(args['email']):
            return {"message": "Email already taken."}, 200
        hashed_password = hash_password(args['password']) 
        new_user = User(name=args['name'], email=args['email'], password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return new_user.user_JSON(), 201

# API class that handles a specific user
class UserAPI(Resource):
    def __init__(self):
        # Argument reguired to be sent in the body of a DELETE to /api/user/<id>
        self.delete_args = reqparse.RequestParser()
        self.delete_args.add_argument("password", type=str, help="Account password is required.", required=True)

        # Argument reguired to be sent in the body of a PUT to /api/user/<id>
        self.post_args= reqparse.RequestParser()
        self.post_args.add_argument("name", type=str, help="Name of user", required=False)
        self.post_args.add_argument("email", type=str, help="User email", required=False)
        self.post_args.add_argument("current_password", type=str, help="Current account password is required.", required=True)
        self.post_args.add_argument("new_password", type=str, help="New account password is required.", required=False)

        # Predefined HTTP responses
        self.msg_user_not_found = {"message": "User not found."}, 404
        self.msg_invalid_password = {"message": "Invalid password."}, 401

    # Returns information about a specific user, specified by the user_id, presented in JSON format
    def get(self, user_id):
        user = User.query.get(user_id)
        if user is None: return self.msg_user_not_found
        return user.user_JSON()

    # Updates the information of a user, given the correct current password of the user
    def put(self, user_id):
        user = User.query.get(user_id)
        if user is None: return self.msg_user_not_found
        args = self.post_args.parse_args()
        if user.verify_password(args['current_password']):
            if args['new_password'] is not None:
                user.password = hash_password(args['new_password'])
            if args['name'] is not None:
                user.name = args['name']
            if args['email'] is not None:
                user.email = args['email']
            db.session.commit()
        else:
            return self.msg_invalid_password
        return '', 200

    # Deletes a user, given the correct user password
    def delete(self, user_id):
        user = User.query.get(user_id)
        if user is None: return self.msg_user_not_found
        password = self.delete_args.parse_args()['password']

        if user.verify_password(password):
            db.session.delete(user)
            db.session.commit()
            return {"message": f'{user} deleted.'}, 200

        return self.msg_invalid_password        

# API class that handles a login request
class Login(Resource):
    def __init__(self):
        # Arguments required to be sent in the body of a POST to /session/login
        self.post_args = reqparse.RequestParser()
        self.post_args.add_argument("email", type=str, help="User email is required.", required=True)
        self.post_args.add_argument("password", type=str, help="Account password is required.", required=True)

        # Predefined HTTP responses
        self.msg_invalid_credentials = {"message": "Invalid email or password."}, 401

    def post(self):
        args = self.post_args.parse_args()
        user = User.query.filter_by(email=args['email']).first()
        if user is None: 
            return self.msg_invalid_credentials
        elif not user.verify_password(args['password']):
            return self.msg_invalid_credentials

        return user.user_JSON(), 200

# API class that handles a filtered search
class Filter(Resource):
    def __init__(self):
        pass
        # Arguments required to be sent in the body of a POST to /api/user/filter
        self.post_args = reqparse.RequestParser()
        self.post_args.add_argument("name", type=str, location="args", help="Name of user is required in search.", required=True)

    # Searches the database for a match given the name of sought after user
    # Search is case-insensitive
    def get(self):
        #args = request.args
        args = self.post_args.parse_args()
        print(args)
        users = User.query.all()
        result = []
        for user in users:
            if re.search(args['name'], user.name, re.IGNORECASE):
                result.append(user)

        return users_JSON(result), 200

api.add_resource(UsersAPI, '/api/user/', methods=['GET', 'POST'])
api.add_resource(UserAPI, '/api/user/', '/api/user/<int:user_id>', methods=['GET', 'PUT', 'DELETE'])
api.add_resource(Login, '/session/login/', methods=['POST'])
api.add_resource(Filter, '/api/user/filter', '/api/user/filter/<name>', methods=['GET'])

if __name__ == '__main__':
    app.run(debug=True)
