import requests, logging

base_url = 'http://localhost:5000/api/'


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

def request_password_reset(email):
    request_body = {'email': email}
    response = requests.post(base_url + 'user/password', json=request_body)
    ret = False, "An error occured"
    if response.status_code == 400:
        ret = False, response.json()['message']
    elif response.status_code == 202:
        ret = True, response.json()['message']
    print('request_password_reset(): ' + str(ret))
    return ret

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

def filter_users(query):
    query_list = query.split(' ')
    query_formatted = '+'.join(query_list)
    request_url = base_url + 'user/filter?name=' + query_formatted
    response = requests.get(request_url)
    print("filter_users(): " + str(response.json()))
    return response.json()['users']

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

if __name__ == '__main__':
    status, user = register_user("a", "b@mail.com", "password2")
    status, user = login('b@mail.com', 'password2')
    status, result = get_user(user['id'], user['session_token'])
    status, result = logout(user['session_token'])
    #status, result = request_password_reset(user['email'])
    #status, result = reset_password("UkitzAyybuFhdg6rvsy6ABdl6cZJuBcyn3hDxcwCcxI", "password2")
    status, result = delete_user(user['id'], "password2")
    status, user = login('b@mail.com', 'password2')
    result = filter_users("a")


    