#!/usr/bin/env python3
"""
"""
from flask import Flask, request, jsonify, abort, make_response
from flask_jwt_extended import JWTManager
from utils import check_password, validate_password_format, validate_email, create_token
from db import Database as storage
from model import User
from os import getenv



app = Flask(__name__)
app.config['JWT_SECRET_KEY'] = getenv('jwt_secret_key')
app.config['JWT_ALGORITHM'] = getenv('jwt_algorithm')
app.url_map.strict_slashes = False
jwt = JWTManager(app)


@app.before_request
def before_request():
    """
    """
    pass


@app.route('/api/v1/register', methods=['POST'])
def signup():
    """
    create user login credentials
    hash user password and save credentials to database
    """
    # validate parameter length
    if len(request.get_json()) > 3:
        return jsonify({'status': 'error',
                        'msg': 'too many request parameters, must be 3'}), 400
    if len(request.get_json()) < 3:
        return jsonify({'status': 'error',
                        'msg': 'not enough request parameters, must be 3'}), 400
    # retrieve user credentials
    user_id = request.json.get('id')
    email = request.json.get('email')
    # valiadate credentials
    if not validate_email(email):
        abort(400)
    password = request.json.get('password')
    if not validate_password_format(password):
        abort(400)
    # check if user exist, if no create new user
    user = User(id=user_id, email=email, password=password)
    user_created = user.save()
    if not user_created:
        return jsonify({'status': 'error', 'msg': 'user already exist'}), 409
    return jsonify({"status": "success", "msg": "credentials created"}), 200


@app.route('/api/v1/login', methods=['POST'])
def signin():
    """
    Logs in user.
    set user cookie user the 'remember me' feature
    returns user access token
    """
    # retrieve user credentials
    email = request.json.get('email')
    password = request.json.get('password')
    # validate credentials
    if password is None or not validate_password_format(password):
        abort(400)
    if email is None:
        abort(400)
    # Validate user credentials
    user = storage().get_one(email=email)
    if not check_password(password, user.get('password')):
        abort(401)
    token = create_token(user.get('id'))
    # checks for RememberMe 
    remember_me = request.json.get('rememberMe')
    if remember_me:
        if not isinstance(remember_me, bool):
            abort(400)
    if remember_me is True:
        # return json response and set cookie
        resp = make_response(jsonify({'status': 'success', 'token': token}))
        resp.set_cookie(getenv('cookie_name'), token)
        return resp, 200
    else:
        return jsonify({'status': 'success', 'token': token}), 200


@app.route('/api/v1/logout', methods=['POST'])
def signout():
    """
    Log out user by removing cookies and invalidating token
    """
    # invalidate user token through message broker (future feature)
    # remove user cookie
    if getenv('cookie_name') in request.cookies:
        response = make_response(jsonify({'status': 'success',
                                          'msg': 'logged out successfully'}))
        response.set_cookie(getenv('cookie_name'), '', expires=0)
        return response
    else:
        return jsonify({'status': 'error',
                        'msg': 'user alreagy logged out'}), 409


@app.errorhandler(400)
def bad_req(error):
    return jsonify({'status': 'error',
                    'msg': 'Bad Request, Please check parameters'}), 400


@app.errorhandler(401)
def unathorized(error):
    return jsonify({'status': 'error', 'msg': ' unauthorized'}), 401


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000)
