from flask import Flask 
from flask_sqlalchemy import SQLAlchemy
from flask_restful import Api, Resource, reqparse
from email.message import EmailMessage
import re, logging, sys, bcrypt, secrets, smtplib

################################################################
#
#
#           Authentication API
#           Author: Leon Philip
#
#
################################################################

# Set upp Flask app, API and database
app = Flask(__name__)
api = Api(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///data.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['BUNDLE_ERRORS'] = True
db = SQLAlchemy(app)

# Class which defined how a user is represented in the database
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    session_token = db.Column(db.String(255))
    reset_token = db.Column(db.String(255))

    # Help function to convert a User object into JSON
    def user_JSON(self):
        response = {'user': {'id': self.id, 'name': self.name, 'email': self.email}}
        return response

    # Help function to convert a User object into JSON also containing session token
    def user_JSON_login(self):
        response = {'user': {'id': self.id, 'name': self.name, 'email': self.email}, "session-token": self.session_token}
        return response

    # Help function which verifies the given password of a user
    def verify_password(self, password):
        password = password.encode('utf-8')
        if bcrypt.checkpw(password, self.password):
            return True
        else:
            return False

    def __repr__(self):
        return f'<User {self.name}:{self.id}>'

# Help function to convert a Users object into JSON
def users_JSON(users):
        response = {'users': []}
        for user in users:
            response['users'].append({'id': user.id, 'name': user.name})
        return response

# Help function which hashes password string, and returns the hashed password
def hash_password(password):
    password = password.encode('utf-8')
    hashed_password = bcrypt.hashpw(password, bcrypt.gensalt(10))
    return hashed_password

# API class which handles requests sent to /api/users.
# Available method is POST, which registers a new user.
class UsersAPI(Resource):
    def __init__(self):
        # Arguments required to be sent in the body of a POST to /api/users
        self.post_args = reqparse.RequestParser()
        self.post_args.add_argument("name", type=str, help="Name of user is required.", required=True)
        self.post_args.add_argument("email", type=str, help="User email is required.", required=True)
        self.post_args.add_argument("password", type=str, help="Account password is required.", required=True)

    # Help function which checks whether an email is already taken
    def email_taken(self, email):
        user_query = User.query.filter_by(email=email).first()
        if user_query is None:
            return False
        else:
            return True

    # Registers a new user, if the email is not already taken
    # Responses: 
    # Success: HTTP status code 201, along with user information in JSON format
    # Failure: HTTP status code 200 - Email already taken
    def post(self):
        args = self.post_args.parse_args()
        if self.email_taken(args['email']):
            return {"message": "Email already taken."}, 200
        hashed_password = hash_password(args['password']) 
        new_user = User(name=args['name'], email=args['email'], password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return new_user.user_JSON(), 201

# API class that handles requests sents to /api/user/<id>.
# Available methods are GET and DELETE.
class UserAPI(Resource):
    def __init__(self):
        self.get_args = reqparse.RequestParser()
        self.get_args.add_argument("session-token", type=str, location="headers", help="Session token is required.", required=True)

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
        self.msg_invalid_token = {"message": "Invalid token."}, 401
        self.msg_not_signed_in = {"message": "User is not signed in."}, 401

    # Returns information about a specific user, specified by the user_id, presented in JSON format
    # Requires session-token, and therefore also requires the user to be signed in.
    # Responses: 
    # Success: HTTP status code 200, along with user information in JSON format
    # Failure: HTTP status code 404: User not found - the specified user id does not exist.
    #          HTTP status code 401: Invalid password - specified password is invalid
    #          HTTP status code 401: Invalid token - specified session token is invalid
    #          HTTP status code 401: User is not signed in
    def get(self, user_id):
        session_token = self.get_args.parse_args()['session-token']
        user = User.query.get(user_id)
        if user is None: 
            return self.msg_user_not_found
        elif user.session_token is None: 
            return self.msg_not_signed_in
        
        if user.session_token != session_token:
            return self.msg_invalid_token

        return user.user_JSON(), 200

    # Deletes a user, given the correct user password
    # Requires user password in request body
    # Responses:
    # Success: HTTP status code 200, along with message "<user> deleted."
    # Failure: HTTP status code 404: User not found - the specified user id does not exist.
    #          HTTP status code 401: Invalid password - specified password is invalid
    def delete(self, user_id):
        user = User.query.get(user_id)
        if user is None: return self.msg_user_not_found
        password = self.delete_args.parse_args()['password']

        if user.verify_password(password):
            db.session.delete(user)
            db.session.commit()
            return {"message": f'{user} deleted.'}, 200

        return self.msg_invalid_password        

# API class that handles requests sent ot /api/session/login
# Available method is POST, which signs in a user.
class Login(Resource):
    def __init__(self):
        # Arguments required to be sent in the body of a POST to /session/login
        self.post_args = reqparse.RequestParser()
        self.post_args.add_argument("email", type=str, help="User email is required.", required=True)
        self.post_args.add_argument("password", type=str, help="Account password is required.", required=True)

        # Predefined HTTP responses
        self.msg_invalid_credentials = {"message": "Invalid email or password."}, 401

    # Log in user.
    # Requires email and password in request body.
    # Responses:
    # Success: HTTP status code 200, along with session token in addition to user information 
    # Failure: HTTP status code 401: Invalid email or password - either email or password is invalid
    def post(self):
        args = self.post_args.parse_args()
        user = User.query.filter_by(email=args['email']).first()
        if user is None: 
            return self.msg_invalid_credentials
        elif not user.verify_password(args['password']):
            return self.msg_invalid_credentials

        if user.session_token is None: 
            session_token = secrets.token_urlsafe()
            user.session_token = session_token
            db.session.commit()

        return user.user_JSON_login(), 200

# API class that handles requests sent to /api/session/logout
# Available method is POST, which sign out user.
class Logout(Resource):
    def __init__(self):
        # Arguments required to be sent in the body of a POST to /session/login
        self.post_args = reqparse.RequestParser()
        self.post_args.add_argument("session-token", type=str, location="headers", help="Session token is required.", required=True)

        # Predefined HTTP responses
        self.msg_invalid_token = {"message": "Invalid session token."}, 401

    # Log out user.
    # requires session-token in headers
    # Responses: 
    # Success: HTTP status code 204, empty body
    # Failure: HTTP status code 401: invalid session token - specified session token is invalid
    def post(self):
        session_token = self.post_args.parse_args()['session-token']
        user = User.query.filter_by(session_token=session_token).first()
        if user is None: 
            return self.msg_invalid_token

        user.session_token = None
        db.session.commit()

        return '', 204

# API class that handles requests sent to /api/user/password/reset.
# Available methods are POST and PUT. POST requests a reset token, and PUT resets
# a users password using the provided reset token.
class ResetPassword(Resource):
    def __init__(self):
        # Arguments required to be sent in the body of a POST to /api/user/password
        self.post_args = reqparse.RequestParser()
        self.post_args.add_argument("email", type=str, help="User email is required.", required=True)

        # Arguments required to be sent in the body of a PUT to /api/user/password
        self.put_args = reqparse.RequestParser()
        self.put_args.add_argument("reset_token", type=str, help="Password reset token is required.", required=True)
        self.put_args.add_argument("new_password", type=str, help="New user password is required.", required=True)

        # Predefined HTTP responses
        self.msg_reset_request = {"message": "If an account with that email exists, an email has been sent with a reset token."}, 202
        self.msg_invalid_token = {"message": "Invalid reset token."}, 401

    # Sends reset token to specified email
    def email_reset_token(self, resettoken, email):
        msg = EmailMessage()
        body = f"A password reset for your account has been requested.\nPlease reset your password using the reset token <{resettoken}>. " + \
        "If you did not request a password reset, please ignore this message."
        msg.set_content(body)
        msg['subject'] = "Password reset requested for your account"
        msg['From'] = "noreply@domain.com"
        msg['To'] = email

        s = smtplib.SMTP('localhost', 1025)
        s.send_message(msg)
        s.quit()

    # Request a password reset, which sends a password reset token to the user
    # Requires user email, and only successfully sends a password reset token if the email is valid
    # Response: HTTP status code 202. Response does not reveal validity of email.
    def post(self):
        email = self.post_args.parse_args()['email']
        user = User.query.filter_by(email=email).first()
        if user is not None:
            resettoken = secrets.token_urlsafe()
            user.reset_token = resettoken
            db.session.commit()
            self.email_reset_token(resettoken, email)
        return self.msg_reset_request

    # Resets the user password using the provided password reset token
    # Requires reset_token and new_password in request body
    # Responses:
    # Success: HTTP status code 200, "Password reset"
    # Failure: HTTP status code 401: Invalid reset token - specified reset token is invalid
    def put(self):
        args = self.put_args.parse_args()
        user = User.query.filter_by(reset_token=args['reset_token']).first()
        if user is None: 
            return self.msg_invalid_token
        elif user.reset_token != args['reset_token']:
            return self.msg_invalid_token
        user.password = hash_password(args['new_password']) 
        user.reset_token = None
        db.session.commit()
        return {"message": "Password reset. Please login using new password."}, 200

# API class that handles requests sent to /api/user/filter.
# Filters users in database based on given query, and returns all users that match.
# Available method is GET.
class Filter(Resource):
    def __init__(self):
        pass
        # Arguments required to be sent in the body of a POST to /api/user/filter
        self.post_args = reqparse.RequestParser()
        self.post_args.add_argument("name", type=str, location="args", help="Name of user is required in search.", required=True)

    # Searches the database for a match given the name of sought after user
    # Requires search query as URL parameter
    # Search is case-insensitive
    # Response: HTTP status code 200, along with matching users in JSON format
    def get(self):
        args = self.post_args.parse_args()
        users = User.query.all()
        result = []
        name = args['name'].split('+')
        name = ' '.join(name)
        for user in users:
            if re.search(args['name'], user.name, re.IGNORECASE):
                result.append(user)

        return users_JSON(result), 200

api.add_resource(UsersAPI, '/api/users/', methods=['POST'])
api.add_resource(UserAPI, '/api/user/', '/api/user/<int:user_id>', methods=['GET', 'DELETE'])
api.add_resource(Login, '/api/session/login/', methods=['POST'])
api.add_resource(Logout, '/api/session/logout/', methods=['POST'])
api.add_resource(Filter, '/api/user/filter', '/api/user/filter/<name>', methods=['GET'])
api.add_resource(ResetPassword, '/api/user/password', methods=['POST', 'PUT'])

if __name__ == '__main__':
    app.run(debug=False)
