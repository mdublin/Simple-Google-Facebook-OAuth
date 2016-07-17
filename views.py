from models import Base, User
from flask import Flask, jsonify, request, url_for, abort, g, render_template
#from flask.ext.session import Session
# had to Google this, it's not included in the "solution code"
from flask import session as login_session
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
from sqlalchemy import create_engine

from flask.ext.login import LoginManager

#from flask.ext.httpauth import HTTPBasicAuth
from flask_httpauth import HTTPBasicAuth, HTTPTokenAuth

import json

# NEW IMPORTS
# https://developers.google.com/api-client-library/python/guide/aaa_oauth
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
from flask import make_response
import requests
import os 

#secret_key = os.environ.get("secret_key")
#print secret_key

auth = HTTPBasicAuth()


engine = create_engine('sqlite:///usersWithOAuth.db')

Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()

app = Flask(__name__)

# not-so-secret_key for sessions, which requires a secret key
# would need to export as environment variable for production
app.secret_key = 'A0Zr98j/3yXR~XHH!jmN]LWX/,?RT'




CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']


# verify_password() is a required function for flask-httpauth so that it knows how we want to validate user credentials
# this is impelemented through the verify_password callback, flask-httpauth uses this callback functionwhenever we need to validate user name and password pair or a token
# the fields in the http header can be used to transport any type of authentication info, for token based auth, the token can be sent as username and the password can be ignored.

'''
@auth.verify_password
def verify_password(username_or_token, password):
    print "verify_password CALLED!!!!!!!!"
    print username_or_token
    print password
    #Try to see if username_or_token is a token first (see this callback in models.py)
    user_id = User.verify_auth_token(username_or_token)
    if user_id:
        user = session.query(User).filter_by(id = user_id).one()
    else:
        user = session.query(User).filter_by(username = username_or_token).first()
        if not user or not user.verify_password(password):
            return False
    g.user = user
    return True

'''


# test for serialized string in Cookie stored in session={serialized data structure containing access token}
# https://flask-httpauth.readthedocs.io/en/latest/#flask_httpauth.HTTPBasicAuth.verify_password
@auth.verify_password
def verify_password(username_or_token, password):
    print "verify_password CALLED!!!!!!!!"
    print username_or_token
    print password

    # This checks if session cookie exists on client, which would only be applied to the client in the event that login via Google was completed successfully 
    if 'session' in request.cookies:
        name_check = login_session['name']
        user = session.query(User).filter_by(username = name_check).first()
        g.current_user = user
        return True
    #Try to see if username_or_token is a token first (see this callback in models.py) 
    user_id = User.verify_auth_token(username_or_token)
    if user_id:
        user = session.query(User).filter_by(id = user_id).one()
    else:
        user = session.query(User).filter_by(username = username_or_token).first()
        if not user or not user.verify_password(password):
            return False
    g.user = user
    return True




'''
login_manager = LoginManager()
@auth.verify_password
def verify_password(email_or_token, password):
    if email_or_token == '':
        g.current_user = login_manager.anonymous_user
        print g.current_user
        return True
    if password == '':
        g.current_user = User.verify_auth_token(email_or_token)
        g.token_user = True
        return g.current_user is not None
    user = User.query.filter_by(email=email_or_token).first()
    if not user:
        return False
    g.current_user = user
    g.token_used = False
    return user.verify_password(password)

'''





@app.route('/clientOAuth')
def start():
    return render_template('clientOAuth.html')



# this currently responds to an AJAX POST request from clientOAuth.html that, if successful, will contain an authorization code provided by Google 
@app.route('/oauth/<provider>', methods=['POST'])
def login(provider):
    print "login endpoint CALLED!!!!!"
    #STEP 1 - Parse the auth code (this is the one-time oauth code we got if the provider parameter is set to Google)
    #auth_code = request.json.get('auth_code')
    
    print "This is the one time oauth code we just got from Google API: %s" % request.data
    
    auth_code = request.data
    print "Step 1 - Complete, received auth code %s" % auth_code
    if provider == 'google':
        #STEP 2 - Exchange for a token
        try:
            # Upgrade the authorization code into a credentials object
            oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
            oauth_flow.redirect_uri = 'postmessage'
            credentials = oauth_flow.step2_exchange(auth_code)
        except FlowExchangeError:
            response = make_response(json.dumps('Failed to upgrade the authorization code.'), 401)
            response.headers['Content-Type'] = 'application/json'
            return response
         

        # Check that the access token is valid.
        access_token = credentials.access_token
        url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s' % access_token)
        h = httplib2.Http()
        result = json.loads(h.request(url, 'GET')[1])
        # If there was an error in the access token info, abort.
        if result.get('error') is not None:
            response = make_response(json.dumps(result.get('error')), 500)
            response.headers['Content-Type'] = 'application/json'
            
        # # Verify that the access token is used for the intended user.
        gplus_id = credentials.id_token['sub']
        if result['user_id'] != gplus_id:
            response = make_response(json.dumps("Token's user ID doesn't match given user ID."), 401)
            response.headers['Content-Type'] = 'application/json'
            return response

        # # Verify that the access token is valid for this app.
        if result['issued_to'] != CLIENT_ID:
            response = make_response(json.dumps("Token's client ID does not match app's."), 401)
            response.headers['Content-Type'] = 'application/json'
            return response

        stored_credentials = login_session.get(credentials.access_token)
        
        #login_session['access_token'] = access_token 
        
        stored_gplus_id = login_session.get('gplus_id')
        print(stored_gplus_id)

        if stored_credentials is not None and gplus_id == stored_gplus_id:
            response = make_response(json.dumps('Current user is already connected.'), 200)
            response.headers['Content-Type'] = 'application/json'
            return response

        print "Step 2 Complete! Access Token : %s " % credentials.access_token

        
        
        #STEP 3 - Find User or make a new one
        
        #Get user info
        h = httplib2.Http()
        userinfo_url =  "https://www.googleapis.com/oauth2/v1/userinfo"
        params = {'access_token': credentials.access_token, 'alt':'json'}
        answer = requests.get(userinfo_url, params=params)
        print "THIS IS answer --- contains userinfo from googleAPIs"
        print(answer.json())

        data = answer.json()

        name = data['name']
        picture = data['picture']
        email = data['email']
       

        print "this is name: %s" % name
     
        #see if user exists, if it doesn't make a new one
        user = session.query(User).filter_by(email=email).first()
        if not user:
            user = User(username = name, picture = picture, email = email)
            session.add(user)
            session.commit()


        #STEP 4 - Make token (this is the token that appears on the test template page under 'Login Successful!')
        # generate_auth_token() is in our User class in models.py
        token = user.generate_auth_token(600)
        
        # assigning access token and user name to session object, which is assigned to the client as a cookie
        login_session['access_token'] = token        
        login_session['name'] = name

        print "user.generate_auth_token(600) == %s" % (token)
        
        #STEP 5 - Send back token to the client 
        #return jsonify({'token': token.decode('ascii')})
        
        return jsonify({'token': token.decode('ascii'), 'duration': 600})
    else:
        return 'Unrecoginized Provider'




@app.route('/token')
@auth.login_required
def get_auth_token():
    token = g.user.generate_auth_token()
    return jsonify({'token': token.decode('ascii')})



@app.route('/users', methods=['POST'])
def new_user():
    username = request.json.get('username')
    password = request.json.get('password')
    if username is None or password is None:
        print "missing arguments"
        abort(400) 
        
    if session.query(User).filter_by(username = username).first() is not None:
        print "existing user"
        user = session.query(User).filter_by(username=username).first()
        return jsonify({'message':'user already exists'}), 200#, {'Location': url_for('get_user', id = user.id, _external = True)}
        
    user = User(username = username)
    user.hash_password(password)
    session.add(user)
    session.commit()
    return jsonify({ 'username': user.username }), 201#, {'Location': url_for('get_user', id = user.id, _external = True)}



@app.route('/api/users/<int:id>')
def get_user(id):
    user = session.query(User).filter_by(id=id).one()
    if not user:
        abort(400)
    return jsonify({'username': user.username})



@app.route('/api/resource')
@auth.login_required
def get_resource():
    #return jsonify({'data': 'hello'})
    #return jsonify({ 'data': 'Hello, %s!' % g.user.username })
    return jsonify({ 'data': 'Hello, %s!' % g.current_user.username })



# http://flask.pocoo.org/docs/0.11/quickstart/#sessions
# testing value assigned to login_session Session object
@app.route('/testSession')
def test_session():
    return jsonify({'access_code': '%s' % login_session['access_token']})


# Note of Flask cookie vs session object:
# this view allows us to attach the access_token as a cookie to the client
# http://flask.pocoo.org/docs/0.11/quickstart/#cookies
# this is using the Flask cookie attribute, which is basically a traditional cookie. 
# You can assign encrypted data to a cookie, like the access_token, but then it is exposed and can be picked
# up with network sniffing, etc. That is why using the session object is the better option, as Flask session object
# creates a cookie in the form of a serialized data structure and takes care of data integrity (i.e. you can store
# a bunch of stuff in the session object as key/value pairs, but the only thing you see when you inspect 
# your browser is a cookie called 'session' with a value that is a long cryptographically signed cookie
# (respresented by an encrypted string)) - What this means is that the user could look at the contents of
# your cookie but not modify it, unless they know the secret key used for signing. That is why, to use the
# session object, you need to create and use a secret_key. 

@app.route('/testCookie')
def test_cookie():
    print "in /testCookie ---> login_session['acess_token']: %s" % login_session['access_token']
    resp = make_response(render_template('googletemplate.html'))
    resp.set_cookie('access_token', login_session['access_token'])
    return resp




# Use this endpoint for examining/confirming that the Flask session cookie (not the 'regular' cookie Flask also provides) has stored itself (as a serialized data structure) on the client
#
@app.route('/sessionCheck')
def session_check():
    print "sessionCheck"
    # checking the global request object for the session cookie, which is a dict with all the contents of all cookies transmitted during the request
    print "Displaying session object, stored as a cookie on the client: %s" % request.cookies
    print login_session
    print login_session['name']
    print login_session['access_token']
    
    
    # checking that the session object, which is a key in the cookie which is a dict data struct, is present in the cookie in the global request object
    if 'session' in request.cookies:
        print True
        session_key_in_cookie = request.cookies['session']
        print session_key_in_cookie
        
    
        return session_key_in_cookie

    return "no session object found in cookie"






@app.route('/')
@auth.login_required
def index():
    return "hello, this is the index"





# this is Google's current Sign-In Button
@app.route('/Googletemplate')
def google_template():
    return render_template('googletemplate.html')






if __name__ == '__main__':
    app.debug = True
    #app.config['SECRET_KEY'] = ''.join(random.choice(string.ascii_uppercase + string.digits) for x in xrange(32))
    app.run(host='localhost', port=5000)


