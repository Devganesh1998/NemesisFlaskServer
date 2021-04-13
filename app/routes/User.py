from . import auth as user
from flask import request, Response
from ..services.auth import register_user, login_user, logout_user, verifyAuth
import json


@user.route('/', methods=['GET'])
def users_home():
    return 'User endpoints Home'


@user.route('/login', methods=['POST'])
def signin():
    data = request.get_json()
    if data is None or data.get('email') is None or data.get('password') is None:
        return Response('{"error": true, "errormsg": "Given payload did not match the required fields", "isLoginSuccess": False, "sampleFormat": {"email": "testmail", "password": "testpassword"}}', status=400, mimetype='application/json')
    res = login_user(data)
    return res


@user.route('/register', methods=['POST'])
def signup():
    data = request.get_json()
    if data is None or data.get('email') is None or data.get('password') is None or data.get('mobile') is None:
        return Response('{"error": true, "errormsg": "Given payload did not match the required fields", "isRegisterSuccess": False, "sampleFormat": {"first_name": "test", "last_name": "mail", "email": "testmail", "password": "testpassword", "mobile": "9736276323"}}', status=400, mimetype='application/json')
    res = register_user(data)
    return res


@user.route('/logout', methods=['GET'])
def logout():
    res = logout_user()
    return res


@user.route('/verifyAuth', methods=['GET'])
def verifyAuthentication():
    res = verifyAuth()
    return json.dumps(res)
