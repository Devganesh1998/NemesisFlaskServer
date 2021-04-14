from ..models import db
from ..models.user import User
import json
import jwt
import datetime
from flask import make_response, request, Response
import traceback 
from flask_bcrypt import generate_password_hash, check_password_hash

authKey = 'secret'
expirationTime = 60 * 5


def register_user(data):
    try:
        hashedPass = generate_password_hash(data.get('password'), 10)
        tempUser = User(
            first_name=data.get('first_name', ''),
            last_name=data.get('last_name', ''),
            email=data['email'],
            password=hashedPass,
            mobile=data['mobile'],
            createdAt=datetime.datetime.now(),
            updatedAt=datetime.datetime.now(),
        )
        db.session.add(tempUser)
        db.session.commit()
        signedEmail = jwt.encode({'email': data['email']}, authKey, 'HS256').decode('utf-8')
        resp = make_response({'error': False, 'isRegisterSuccess': True, 'message': 'Registered Successfully',
                              'user': {'email': data['email']}})
        resp.headers.add('Access-Control-Allow-Headers', 'X-Requested-With, X-HTTP-Method-Override, Content-Type, Accept')
        resp.set_cookie('signedEmail', str(signedEmail), max_age=expirationTime, httponly=True, samesite='None', secure=True)
        return resp
    except Exception as err:
        print(err)
        if (err.args[0] == '(MySQLdb._exceptions.IntegrityError) (1062, "Duplicate entry \'testmail\' for key \'users.email\'")'):
            return Response('{"error": true, "errormsg": "Given email has already an account", "isRegisterSuccess": false, "sampleFormat": {"first_name": "test", "last_name": "mail", "email": "testmail", "password": "testpassword", "mobile": "9736276323"}}', status=400, mimetype='application/json')
        traceback.print_exc() 
        return Response('{"error": true, "errormsg": "Internal Server Error", "isRegisterSuccess": false, "sampleFormat": {"first_name": "test", "last_name": "mail", "email": "testmail", "password": "testpassword", "mobile": "9736276323"}}', status=500, mimetype='application/json')


def login_user(credentials):
    try:
        email = credentials['email']
        password = credentials['password']
        results = User.query.filter(User.email == email).first()
        if (results != None and check_password_hash(results.password.encode('utf8'), password)):
            signedEmail = jwt.encode({'email': email}, authKey, 'HS256').decode('utf-8')
            resp = make_response({'error': False, 'message': 'Login Successful',
                                  'isLoginSuccess': True, 'user': {'email': email}})
            resp.headers.add('Access-Control-Allow-Headers', 'X-Requested-With, X-HTTP-Method-Override, Content-Type, Accept')
            resp.set_cookie('signedEmail', str(signedEmail), max_age=expirationTime, httponly=True, samesite='None', secure=True)
            return resp
        else:
            return Response('{"error": true, "errormsg": "Incorrect Password", "isLoginSuccess": false, "sampleFormat": {"email": "testmail", "password": "testpassword"}}', status=400, mimetype='application/json')
    except Exception as err:
        print(err)
        traceback.print_exc() 
        return Response('{"error": true, "errormsg": "Internal server error", "isLoginSuccess": false, "sampleFormat": {"email": "testmail", "password": "testpassword"}}', status=500, mimetype='application/json')


def logout_user():
    try:
        signedEmail = request.cookies.get('signedEmail')
        resp = make_response({'isLogoutSuccess': True})
        resp.set_cookie('signedEmail', '', max_age=0)
        return resp
    except Exception as err:
        print(err)
        traceback.print_exc() 
        return Response('{"errormsg": "Internal server error", "isLogoutSuccess": false}', status=500, mimetype='application/json')


def verifyAuth():
    try:
        signedEmail = request.cookies.get('signedEmail')
        if signedEmail is not None:
            signedEmailPayload = jwt.decode(signedEmail, authKey, algorithms=['HS256'])
            if signedEmailPayload is not None and signedEmailPayload['email'] is not None:
                return Response('{"isAuthenticated": true, "user": { "email": "' + signedEmailPayload['email'] + '" }}', status=200, mimetype='application/json')
        return Response('{"message": "Session Expired", "isAuthenticated": false}', status=200, mimetype='application/json')
    except Exception as err:
        print(err)
        traceback.print_exc() 
        return Response('{"error": true, "errormsg": "Internal server error", "isAuthenticated": false }', status=500, mimetype='application/json')
