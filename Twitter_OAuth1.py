import requests
from hashlib import sha1
import hmac
import base64
import os
import time

# All key/value pairs needed for authorizing requests sent to Twitter API:
# https://dev.twitter.com/oauth/overview/authorizing-requests


# consumer key
oauth_consumer_key = ""


# valid access token
oauth_token = ""


# OAuth version number
oauth_version = "1.0"


# generate nonce
def make_nonce():
    randomness = os.urandom(32)
    base64_encode_it = base64.b64encode(randomness)
    oauth_nonce = base64_encode_it
    if oauth_nonce.isalnum() == False:
        # creating a string of non-alphanumeric characters to check against
        delchars = ''.join(c for c in map(chr, range(256)) if not c.isalnum())
        # using string.translate, no table used because we are not actually
        # making a translation, so that is set to None, and for the delete
        # positional, passing the delchars string
        oauth_nonce = oauth_nonce.translate(None, delchars)

    return oauth_nonce


# generate timestamp
def timestamp():
    oauth_timestamp = time.time()
    return oauth_timestamp


# signature method
oauth_signature_method = "HMAC-SHA1"


# generate required HMAC-SHA1 signature
def generate_sig():
    sig = ""
    sig_base = ""
    hashed = hmac.new(sig, sig_base, sha1)
    hashed.digest().encode("base64").rstrip('\n')

    return oauth_signature
