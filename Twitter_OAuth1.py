import requests
from hashlib import sha1
import hmac
import base64
import os
import time
import json
from urllib import quote_plus

# All key/value pairs needed for authorizing requests sent to Twitter API:
# https://dev.twitter.com/oauth/overview/authorizing-requests
# http://stackoverflow.com/questions/8338661/implementaion-hmac-sha1-in-python

# get Twitter OAuth app credentials
with open('twitter_creds.json', 'r') as f:
    data = json.load(f)


# consumer key
oauth_consumer_key = data['consumer_key']

# consumer secret
oauth_consumer_secret = data['consumer_secret']

# valid access token
oauth_access_token = data['access_token']

# OAuth version number
oauth_version = "1.0"


# generate nonce
def make_nonce():
    randomness = os.urandom(32)
    base64_encode_it = base64.b64encode(randomness)
    oauth_nonce = base64_encode_it
    if oauth_nonce.isalnum() is False:
        # creating a string of non-alphanumeric characters to check against
        delchars = ''.join(c for c in map(chr, range(256)) if not c.isalnum())
        # using string.translate, no table used because we are not actually
        # making a translation, so that is set to None, and for the delete
        # positional, passing the delchars string
        oauth_nonce = oauth_nonce.translate(None, delchars)

    return oauth_nonce


# signature method
oauth_signature_method = "HMAC-SHA1"


def create_signature():
    ''' just for getting request_token
    https://dev.twitter.com/oauth/overview/creating-signatures
     '''

    output_string = ""
    parameter_string = ""
    # collect parameters

    HTTPMethod = "POST"
    BaseURL = "https://api.twitter.com/oauth/request_token"

    oauth_callback = quote_plus(
        "https://github.com/mdublin/Simple-Google-Facebook-OAuth")
    oauth_consumer_key = quote_plus("#### ENTER Consumer Key ####")
    oauth_nonce = quote_plus(make_nonce())
    oauth_signature_method = quote_plus("HMAC-SHA1")
    oauth_timestamp = quote_plus(timestamp())
    oauth_version = quote_plus("1.0")

    package = {}
    package["oauth_callback"] = oauth_callback
    package["oauth_consumer_key"] = oauth_consumer_key
    package["oauth_nonce"] = oauth_nonce
    package["oauth_signature_method"] = oauth_signature_method
    package["oauth_timestamp"] = oauth_timestamp
    package["oauth_version"] = oauth_version
    package["BaseURL"] = BaseURL
    package["HTTPMethod"] = HTTPMethod

    oauth_callback = "oauth_callback=%s" % oauth_callback
    parameter_string = oauth_callback + "&"

    oauth_consumer_key = "oauth_consumer_key=%s" % oauth_consumer_key
    parameter_string = parameter_string + oauth_consumer_key + "&"

    oauth_nonce = "oauth_nonce=%s" % oauth_nonce
    parameter_string = parameter_string + oauth_nonce + "&"

    oauth_signature_method = "oauth_signature_method=%s" % oauth_signature_method
    parameter_string = parameter_string + oauth_signature_method + "&"

    oauth_timestamp = "oauth_timestamp=%s" % oauth_timestamp
    parameter_string = parameter_string + oauth_timestamp + "&"

    oauth_version = "oauth_version=%s" % oauth_version
    parameter_string = parameter_string + oauth_version

    # paramter string
    print(parameter_string)

    # build output_string
    output_string = HTTPMethod + "&"
    BaseURL = quote_plus(BaseURL)
    output_string = output_string + BaseURL + "&"
    parameter_string = quote_plus(parameter_string)
    signature_base_string = output_string + parameter_string

    print(signature_base_string)

    # get signing key
    consumer_secret = "####ENTER Consumer Secret (API Secret)#####"
    signing_key = quote_plus(consumer_secret) + "&"

    oauth_signature = calculate_signature(signature_base_string, signing_key)

    # package full of stuff to return to request_access_token()
    oauth_signature = quote_plus(oauth_signature)
    package["oauth_signature"] = oauth_signature

    return package


def timestamp():
    oauth_timestamp = time.time()
    return str(int(oauth_timestamp))


def get_signing_key():
    '''
    for getting request_token only, we just need oauth_consumer_secret
    '''
    signing_key = quote_plus(oauth_consumer_secret) + '&'
    return signing_key


def calculate_signature(signature_base_string, signing_key):
    '''
    HMAC-SHA1 hasing algorithm that
    returns final oauth signature for the request_token
    request
    '''
    key = signing_key
    raw = signature_base_string

    # pass signing key and base string to the HMAC1-SHA1 hashing algorithm
    hashed = hmac.new(key, raw, sha1)
    # output of hashed is binary string, so this needs to be base64 encoded to
    # produce signature string
    sig = hashed.digest().encode("base64").rstrip('\n')
    return sig


def request_access_token():

    # call create_signature() to get oauth_signature as well as all other
    # parameters for Authorization Header
    get_sig_and_header = create_signature()

    oauth_nonce = get_sig_and_header["oauth_nonce"]
    oauth_callback = get_sig_and_header["oauth_callback"]
    oauth_signature_method = get_sig_and_header["oauth_signature_method"]
    oauth_timestamp = get_sig_and_header["oauth_timestamp"]
    oauth_consumer_key = get_sig_and_header["oauth_consumer_key"]
    oauth_signature = get_sig_and_header["oauth_signature"]
    oauth_version = get_sig_and_header["oauth_version"]

    header_values = ''

    # build header values string
    Authorization_Header = 'OAuth oauth_nonce="%s", oauth_callback="%s", oauth_signature_method="%s", oauth_timestamp="%s", oauth_consumer_key="%s", oauth_signature="%s", oauth_version="%s"' % (
        oauth_nonce, oauth_callback, oauth_signature_method, oauth_timestamp, oauth_consumer_key, oauth_signature, oauth_version)

    # instantiate header dict
    headers = {}
    headers["Authorization"] = str(Authorization_Header)

    url = "https://api.twitter.com/oauth/request_token"

    # POST request for request_token
    r = requests.post(url, headers=headers)

    return r.text
