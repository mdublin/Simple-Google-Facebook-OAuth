from models import Base, User
from flask import Flask, jsonify, request, url_for, abort, g, render_template, redirect

# Flask-Cors
#from flask_cors import CORS, cross_origin

#from flask.ext.session import Session
# had to Google this, it's not included in the "solution code"
from flask import session as login_session
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
from sqlalchemy import create_engine

from flask.ext.login import LoginManager

#from flask.ext.httpauth import HTTPBasicAuth
from flask_httpauth import HTTPBasicAuth, HTTPTokenAuth

# rauth for handling Twitter OAuth 1.0 requirements
from rauth import OAuth1Service
# importing our Twitter OAuth1 module
import Twitter_OAuth1

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
# print secret_key

auth = HTTPBasicAuth()


engine = create_engine('sqlite:///usersWithOAuth.db')

Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()

app = Flask(__name__)

# initializing Flask-Cors extension with default arguments to allow CORS
# support on on all routes, for all origins and methods.
# CORS(app)


# not-so-secret_key for sessions, which requires a secret key
# would need to export as environment variable for production
app.secret_key = 'A0Zr98j/3yXR~XHH!WX/,?RT'


CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']


# verify_password() is a required function for flask-httpauth so that it knows how we want to validate user credentials
# this is impelemented through the verify_password callback, flask-httpauth uses this callback functionwhenever we need to validate user name and password pair or a token
# the fields in the http header can be used to transport any type of
# authentication info, for token based auth, the token can be sent as
# username and the password can be ignored.


# test for serialized string in Cookie stored in session={serialized data structure containing access token}
# https://flask-httpauth.readthedocs.io/en/latest/#flask_httpauth.HTTPBasicAuth.verify_password
@auth.verify_password
def verify_password(username_or_token, password):
    print "verify_password CALLED!!!!!!!!"
    print username_or_token
    print password

    # This checks if session cookie exists on client, which would only be
    # applied to the client in the event that login via Google was completed
    # successfully
    if 'session' in request.cookies:
        name_check = login_session['name']
        user = session.query(User).filter_by(username=name_check).first()
        g.current_user = user
        return True
    # Try to see if username_or_token is a token first (see this callback in
    # models.py)
    user_id = User.verify_auth_token(username_or_token)
    if user_id:
        user = session.query(User).filter_by(id=user_id).one()
    else:
        user = session.query(User).filter_by(
            username=username_or_token).first()
        if not user or not user.verify_password(password):
            return False
    g.user = user
    return True


@app.route('/clientOAuth_Google')
def start():
    return render_template('clientOAuth_Google.html')


# Login via Facebook Authentication
@app.route('/clientOAuth_Facebook')
def start_2():
    return render_template('clientOAuth_Facebook.html')


# Login via Twitter Authentication
@app.route('/clientOAuth_Twitter')
def start_3():
    return render_template('clientOAuth_Twitter.html')

# global dict used to store all items in successful access_token_response
# in Twitter OAuth 1.0 flow
access_token_response_package = {}


@app.route('/Twitter_callback')
def twitter_callback():
    try:
        callback_param_oauth_token = request.args.get('oauth_token')
        callback_param_oauth_verifier = request.args.get('oauth_verifier')

        # taking oauth_token and oauth_verifier and passing to access_token(), the function that handles the last
        # step in the OAuth 1.0 flow
        # if successful, this returns oauth_token, oauth_token_secret, user_id,
        # screen_name
        access_token_response = Twitter_OAuth1.access_token(
            callback_param_oauth_token, callback_param_oauth_verifier)

        for index, item in enumerate(access_token_response):
            separate = item.split("=")
            access_token_response_package[separate[0]] = separate[1]
        print(access_token_response_package)

        if access_token_response_package:
            # see if user (in this case, Twitter user_id) exists, if it doesn't
            # make a new one
            user = session.query(User).filter_by(
                twitter_user_id=access_token_response_package["user_id"]).first()

            if not user:
                user = User(
                    twitter_user_id=access_token_response_package["user_id"])
                session.add(user)
                session.commit()
                return render_template(
                    'twitter_callback.html',
                    user_name=access_token_response_package["screen_name"])
            else:
                return render_template('twitter_callback.html')
        # rendering oauth_token and oauth_verifer params contained in callback_url after successful completion of
        # # step 2 in the OAuth 1.0 flow
        # return render_template('twitter_callback.html',
        # callback_param_oauth_token=callback_param_oauth_token,
        # callback_param_oauth_verifier=callback_param_oauth_verifier)
    except KeyError:
        return("Something went wrong with the Twitter Authentication, missing oauth_token and oauth_verifier parms in URL")


@app.route('/testFB_cookie')
def test_fb_cookie():
    print request.cookies
    # print request.cookies.get["fbsr_266475267061303"]
    #fb_cookie = request.cookies.get("fbsr_266475267061303")
    print fb_cookie
    return jsonify({'fb_cookie': '%s' % fb_cookie})


'''
For login endpoint currently responds to an AJAX POST request from Facebook and Google clientOAuth.html views. Adding 'GET' to methods for /clientOAuth_Twitter, which uses a Twitter sign in button that uses jinja instead of AJAX (see comments in clientOAuth_Twitter for more info, but basically Twitter API does not support CORS, that is why we need to do everything server-side). But url_for in jinja can only send GET requests to endpoint, because all links are GET requests, right? So if we did not divert the GET request, itwould just try and render this view with /oauth/twitter like a normal view except it would return a 405 error.
'''


@app.route('/oauth/<provider>', methods=['GET', 'POST'])
def login(provider):

    print "login endpoint CALLED!!!!!"
    # STEP 1 - Parse the auth code (this is the one-time oauth code we got if the provider parameter is set to Google)
    #auth_code = request.json.get('auth_code')

    auth_code = request.data
    print "Step 1 - Complete, received auth code: %s" % auth_code

    # FACEBOOK
    if provider == 'facebook':
        # use to see request header
        # print(request.headers.get)
        FB_authorized_response = request.data
        # converting JSON.stringify(authPackage) to dict with json.loads so it
        # is not just a string that looks like JSON
        FB_authorized_response = json.loads(FB_authorized_response)
        s
        # make FB authorized response dict
        fb_access_code = FB_authorized_response["fb_access_code"]
        fb_user_name = FB_authorized_response["user_info"]["name"]
        fb_user_id = FB_authorized_response["user_info"]["id"]
        Facebook_OAuth_response = {
            'Facebook_access_code': fb_access_code,
            'Facebook_username': fb_user_name,
            'Facebook_user_id': fb_user_id}
        print(Facebook_OAuth_response)

        # see if FB user exists in db
        user = session.query(User).filter_by(username=fb_user_name).first()
        if not user:
            user = User(username=fb_user_name, fb_user_id=fb_user_id)
            session.add(user)
            session.commit()

        return jsonify(Facebook_OAuth_response)

    # TWITTER
    if (provider == "twitter") and (request.method == 'GET'):
        get_request_token = Twitter_OAuth1.request_token()
        get_oauth_token = get_request_token.split("&")
        print(get_oauth_token)
        get_oauth_token = get_oauth_token[0]
        oauth_authenticate_redirect = "https://api.twitter.com/oauth/authenticate?%s" % get_oauth_token
        return redirect(oauth_authenticate_redirect)

    # GOOGLE
    if provider == 'google':
        # STEP 2 - Exchange for a token
        try:
            # Upgrade the authorization code into a credentials object
            oauth_flow = flow_from_clientsecrets(
                'client_secrets.json', scope='')
            oauth_flow.redirect_uri = 'postmessage'
            credentials = oauth_flow.step2_exchange(auth_code)
        except FlowExchangeError:
            response = make_response(
                json.dumps('Failed to upgrade the authorization code.'), 401)
            response.headers['Content-Type'] = 'application/json'
            return response

        # Check that the access token is valid.
        access_token = credentials.access_token
        url = (
            'https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s' %
            access_token)
        h = httplib2.Http()
        result = json.loads(h.request(url, 'GET')[1])

        # If there was an error in the access token info, abort.
        if result.get('error') is not None:
            response = make_response(json.dumps(result.get('error')), 500)
            response.headers['Content-Type'] = 'application/json'

        # Verify that the access token is used for the intended user.
        gplus_id = credentials.id_token['sub']
        if result['user_id'] != gplus_id:
            response = make_response(
                json.dumps("Token's user ID doesn't match given user ID."), 401)
            response.headers['Content-Type'] = 'application/json'
            return response

        # Verify that the access token is valid for this app.
        if result['issued_to'] != CLIENT_ID:
            response = make_response(
                json.dumps("Token's client ID does not match app's."), 401)
            response.headers['Content-Type'] = 'application/json'
            return response

        stored_credentials = login_session.get(credentials.access_token)

        #login_session['access_token'] = access_token

        stored_gplus_id = login_session.get('gplus_id')
        print(stored_gplus_id)

        if stored_credentials is not None and gplus_id == stored_gplus_id:
            response = make_response(
                json.dumps('Current user is already connected.'), 200)
            response.headers['Content-Type'] = 'application/json'
            return response

        print "Step 2 Complete! Access Token : %s " % credentials.access_token

        # STEP 3 - Find User or make a new one

        # Get user info
        h = httplib2.Http()
        userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
        params = {'access_token': credentials.access_token, 'alt': 'json'}
        answer = requests.get(userinfo_url, params=params)
        print "THIS IS answer --- contains userinfo from googleAPIs"
        print(answer.json())

        data = answer.json()

        name = data['name']
        picture = data['picture']
        email = data['email']

        print "this is name: %s" % name

        # see if user exists, if it doesn't make a new one
        user = session.query(User).filter_by(email=email).first()
        if not user:
            user = User(username=name, picture=picture, email=email)
            session.add(user)
            session.commit()

        # STEP 4 - Make token (this is the token that appears on the test template page under 'Login Successful!')
        # generate_auth_token() is in our User class in models.py
        token = user.generate_auth_token(600)

        # assigning access token and user name to session object, which is
        # assigned to the client as a cookie
        login_session['access_token'] = token
        login_session['name'] = name

        print "user.generate_auth_token(600) == %s" % (token)

        # STEP 5 - Send back token to the client
        # return jsonify({'token': token.decode('ascii')})

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

    if session.query(User).filter_by(username=username).first() is not None:
        print "existing user"
        user = session.query(User).filter_by(username=username).first()
        # , {'Location': url_for('get_user', id = user.id, _external = True)}
        return jsonify({'message': 'user already exists'}), 200

    user = User(username=username)
    user.hash_password(password)
    session.add(user)
    session.commit()
    # , {'Location': url_for('get_user', id = user.id, _external = True)}
    return jsonify({'username': user.username}), 201


@app.route('/api/users/<int:id>')
def get_user(id):
    user = session.query(User).filter_by(id=id).one()
    if not user:
        abort(400)
    return jsonify({'username': user.username})


@app.route('/api/resource')
@auth.login_required
def get_resource():
    # return jsonify({'data': 'hello'})
    # return jsonify({ 'data': 'Hello, %s!' % g.user.username })
    return jsonify({'data': 'Hello, %s!' % g.current_user.username})


# http://flask.pocoo.org/docs/0.11/quickstart/#sessions
# testing value assigned to login_session Session object
@app.route('/testSession')
def test_session():
    return jsonify({'access_code': '%s' % login_session['access_token']})


'''
Note of Flask cookie vs session object:
This view allows us to attach the access_token as a cookie to the client
http://flask.pocoo.org/docs/0.11/quickstart/#cookies
this is using the Flask cookie attribute, which is basically a traditional cookie.
You can assign encrypted data to a cookie, like the access_token, but then it is exposed and can be picked up with network sniffing, etc. That is why using the session object is the better option, as Flask session object creates a cookie in the form of a serialized data structure and takes care of data integrity (i.e. you can store a bunch of stuff in the session object as key/value pairs, but the only thing you see when you inspect your browser is a cookie called 'session' with a value that is a long cryptographically signed cookie
(respresented by an encrypted string)) - What this means is that the user could look at the contents of
your cookie but not modify it, unless they know the secret key used for signing. That is why, to use the
session object, you need to create and use a secret_key.

'''


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
    # checking the global request object for the session cookie, which is a
    # dict with all the contents of all cookies transmitted during the request
    print "Displaying session object, stored as a cookie on the client: %s" % request.cookies
    print login_session
    print login_session['name']
    print login_session['access_token']

    # checking that the session object, which is a key in the cookie which is
    # a dict data struct, is present in the cookie in the global request
    # object
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
