import requests

base_url = 'http://localhost:5000/api/'

############################################################################
#
#           CLIENT API ENDPOINT FUNCTIONS
#
###########################################################################

# Registers a new user by sending POST to /api/users
# Requires name, email and password
# Returns True, <user as JSON> if successful
# Returns False, <error> if unsuccessful
def register_user(name, email, password):
    request_body = {
        'name': name,
        'email': email,
        'password': password
    }
    response = requests.post(base_url + 'users', json=request_body)
    ret = False, "An error occured"
    if response.status_code == 200:
        ret = False, response.json()['message']
    elif response.status_code == 201:
        ret = True, response.json()
    print('regsiter_user(): ' + str(ret))
    return ret

# Gets user information by sending GET to /api/user/<id>
# Requires user id and session token
# Returns True, <user as JSON> if successful
# Returns False, <error> if unsuccessful
def get_user(user_id, session_token):
    request_headers = {'session_token': session_token}
    response = requests.get(base_url + 'user/' + str(user_id), headers=request_headers)
    ret = False, "An error occured"
    if response.status_code == 404 or response.status_code == 401:
        ret = False, response.json()['message']
    elif response.status_code == 200:
        data = response.json()
        user = {
            'id': data['user']['id'],
            'name': data['user']['name'],
            'email': data['user']['email'],
        }
        ret = True, user
    print('get_user(): ' + str(ret))
    return ret

# Deletes a user by sending DELETE to /api/user/<id>
# Requires user id and password
# Returns True, <response> if successful
# Returns False, <error> if unsuccessful
def delete_user(user_id, password):
    request_body = {'password': password}
    response = requests.delete(base_url + 'user/' + str(user_id), json=request_body)
    ret = False, "An error occured"
    if response.status_code == 401 or response.status_code == 404:
        ret = False, response.json()['message']
    elif response.status_code == 200:
        ret = True, response.json()
    print('delete_user(): ' + str(ret))
    return ret

# Requests a password reset by sending POST to /api/user/password
# Requires user email
# Returns True, <response> if successful
# Returns False, <error> if unsuccessful
def request_password_reset(email):
    request_body = {'email': email}
    response = requests.post(base_url + 'user/password', json=request_body)
    ret = False, "An error occured"
    if response.status_code == 202:
        ret = True, response.json()['message']
    print('request_password_reset(): ' + str(ret))
    return ret

# Resets the password of a user
# Requires reset token and new password
# Returns True, <response> if successful
# Returns False, <error> if unsuccessful
def reset_password(reset_token, new_password):
    request_body = {
        "reset_token": reset_token,
        "new_password": new_password
    }
    response = requests.put(base_url + 'user/password', json=request_body)
    ret = False, "An error occured"
    if response.status_code == 401:
        ret = False, response.json()['message']
    elif response.status_code == 200:
        ret = True, response.json()['message']
    print('reset_password(): ' + str(ret))
    return ret

# Filters the database for users matching the specified query
# Requires search query
# Returns query result in JSON format
def filter_users(query):
    query_list = query.split(' ')
    query_formatted = '+'.join(query_list)
    request_url = base_url + 'user/filter?name=' + query_formatted
    response = requests.get(request_url)
    print("filter_users(): " + str(response.json()))
    return response.json()['users']

# Log in a user
# Requires user email and password
# Returns True, <user as JSON with session token> if successful
# Returns False, <error> if unsuccessful
def login(email, password):
    request_body = {'email': email, 'password': password}
    response = requests.post(base_url + 'session/login', json=request_body)
    ret = False, "An error occured"
    if response.status_code == 401:
        ret = False, response.json()['message']
    elif response.status_code == 200:
        data = response.json()
        user = {
            'id': data['user']['id'],
            'name': data['user']['name'],
            'email': data['user']['email'],
            'session_token': data['session-token']
        }
        ret = True, user
    print("login(): " + str(ret))
    return ret

# Log out user
# Requires session token
# Returns True, "Success!" if successful
# Returns False, <error> if unsuccessful
def logout(session_token):
    request_headers = {'session-token': session_token}
    response = requests.post(base_url + 'session/logout', headers=request_headers)
    ret = False, "An error occured"
    if response.status_code == 401:
        ret = False, response.json()['message']
    elif response.status_code == 204:
        ret = True, "Success!"
    print('logout(): ' + str(ret))
    return ret