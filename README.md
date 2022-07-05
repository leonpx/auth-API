# Authentication REST API
A REST API written in Python with account management functionality.

## Python dependencies
- `Flask==2.1.2`
- `Flask-RESTful==0.3.9`
- `Flask-SQLAlchemy==2.5.1`
- `bcrypt==3.2.2`

## API
### /api/users
- `POST`: register a new user. Name, Email and Password in JSON format required, example:
```json
{
    "name": "Name name",
    "email": "name@mail.com",
    "password": "secret"
}
```
### /api/user/\<id>
- `GET`: retrieve information about logged in user with \<id>. Session token is required in headers. Example:
```
GET /api/user/2 HTTP/1.1
Host: 127.0.0.1:5000
sessiontoken: <secret>
```
- `DELETE`: deletes a user. User password is required.
### /api/user/password
- `POST`: request a new user password. Account email is required. A reset token will be sent to the specified email.
- `PUT`: reset the password of a user. Reset token and new password is required.

### /api/user/filter
- `GET`: queries the database for users that match the given name as URL parameter. Spaces are delimited by a plus sign. Example:
```
<webserver>/api/user/filter?name=Adam+Smith
```
### /api/session/login
- `POST`: create a new session. Account email and password is required. Session token is returned upon successful login.
```json
{
    "email": "name@mail.com"
    "password": "secret"
}
```
### /api/session/logout
- `POST`: end a session. Session token is required in headers.

