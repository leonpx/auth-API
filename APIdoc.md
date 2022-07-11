# Auth-API documentation
# /api/users
## POST /api/users
Register a new user. Requires name, email and password in JSON format sent in body.

### Example request
`POST http://example.com/api/users`\
```json
{
    "name": "Adam Smith",
    "email": "adam@smith.com",
    "password": "secret"
}
```

### Example response
```json
{
    "user": {
        "id": 1,
        "name": "Adam Smith",
        "email": "adam@smith.com"
    }
}
```

### Errors
- Code 200: "Email already taken". An account with that email already exists.

# /api/user/\<id>
## GET /api/user/\<id>
Retrieve information about logged in user with \<id>. Requires session token in headers. 

### Example request
```
GET http://example.com/api/user/1 HTTP/1.1
Host: example.com
session-token: <secret>
```

### Example response
```json
{
    "user": {
        "id": 1,
        "name": "Adam Smith",
        "email": "adam@smith.com"
    }
}
```
### Errors
- Code 401: "Invalid token". The specified session token is invalid.
- Code 401: "User is not signed in". 
- Code 404: "User not found". A user with the specified id does not exist.

## DELETE /api/user/\<id>
Deletes a user. Requires user password in JSON format in request body.

### Example request
`DELETE http://example.com/api/user/1`
```json
{
    "password": "secret"
}
```

### Example response
```json
{
    "message": "<User Adam:adam@smith.com> deleted."
}
```

### Errors
- Code 401: "Invalid password".
- Code 404: "User not found". A user with the specified id does not exist.


# /api/user/password
## POST /api/user/password
Request a password reset token, used for resetting the password of an account. Requires account email in JSON format in request body. A reset token will be sent to the specified email, if it is valid.

### Example request
`POST http://example.com/api/user/password`
```json
{
    "email": "adam@smith.com"
}
```

### Example response
```json
{
    "message": "If an account with that email exists, an email has been sent with a reset token."
}
```

## PUT /api/user/password
Reset the password of a user. Requires reset token and new password in JSON format in request body.

### Example request
`PUT http://example.com/api/user/password`
```json
{
    "reset_token": "secret"
    "new_password": "secret"
}
```

### Example response
```json
{
    "message": "Password reset. Please login using new password."
}
```

### Errors
- Code 401: "Invalid reset token"

# /api/user/filter
## GET /api/user/filter
Queries the database for users that match the given name as URL parameter. Spaces are delimited by a plus sign. Ignores leading and trailing whitespace.

### Example request
```
http://example.com/api/user/filter?name=Adam
```

### Example response
```json
{
    "users": [
        {
            "id": 1,
            "name": "Adam Smith"
        },
        {
            "id": 2,
            "name": "Adam Jones"
        }
    ]
}
```
# /api/session/login
## POST /api/session/login
Create a new session. Requires email and password is required as JSON in request body. Session token is returned upon successful login.

### Example request
`POST http://example.com/api/session/login`
```json
{
    "email": "adam@smith.com"
    "password": "secret"
}
```

### Example response
```json
{
    "user": {
        "id": 1,
        "name": "Adam Smith",
        "email": "adam@smith.com"
    },
    "session-token": "M5LwMdUWc5ULLkeHoJ3R3zZxF218__9dqXdCUBNyIF4"
}
```

### Errors
- Code 401: "Invalid email or password".

# /api/session/logout
## POST /api/session/logout
End a session. Requires Session token in headers.

### Example request
```
POST http://example.com/api/session/logout HTTP/1.1
Host: example.com
session-token: <secret>
```

### Example response
Empty body, response code 204.

### Errors
- Code 401: "Invalid session token"