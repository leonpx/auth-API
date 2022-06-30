# Authentication REST API
A REST API written in Python with account management functionality.

## Python dependencies
- `aniso8601==9.0.1`
- `Authlib==1.0.1`
- `cffi==1.15.0`
- `click==8.1.3`
- `cryptography==37.0.2`
- `Flask==2.1.2`
- `Flask-RESTful==0.3.9`
- `Flask-SQLAlchemy==2.5.1`
- `greenlet==1.1.2`
- `itsdangerous==2.1.2`
- `Jinja2==3.1.2`
- `MarkupSafe==2.1.1`
- `pycparser==2.21`
- `pytz==2022.1`
- `six==1.16.0`
- `SQLAlchemy==1.4.39`
- `Werkzeug==2.1.2`

## API
### /api/user
- `GET`: retrieve all registered users and their information
- `POST`: register a new user. Name, Email and Password in JSON format required, example:
```json
{
    "name": "Name name",
    "email": "name@mail.com",
    "password": "secret"
}
```
### /api/user/<id>
- `GET`: retrieve information about user with <id>
- `PUT`: update user information. Current user password is required, and account information is updated if specified. Example updating name and password:
```json
{
    "name": "Name name",
    "current_password": "secret",
    "new_password": "new_secret"
}
```
- `DELETE`: deletes a user. User password is required.
### /api/user/filter
- `GET`: queries the database for users that match the given name as URL parameter. Example:
```
<webserver>/api/user/filter?name=Adam
```
### /api/session/login
- `POST`: create a new session. Account email and password is required.
### /api/session/logout
- `POST`: end a session. Authentication token is required.

