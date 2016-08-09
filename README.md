For Google OAuth:

You need to visit the Google Cloud Platform, and register an app or create a project, and grab the credentials from the API Manager (the Server key and Web client OAuth 2.0 client ID)

To set the Authorized redirect URI, go here:

`https://console.cloud.google.com/apis/credentials/oauthclient`

Just make sure, when doing local development, that you set the Authorized Redirect URIs and Authorized JavaScript Origins to `http://localhost:8000` and not `http://127.0.0.1:8000` as the Google servers won't deal with 'URL fragments or relative paths' and 'cannot be a public IP address', hence the need for a hostname and not IP address. 

Download the client_secret.json file from the OAuth 2.0 client IDs section. 

Add the `client_ID` to the JS in the clientOAuth_Google.html view.


Regarding Twitter OAuth 1.0 flow:

1. In your Twitter dev account, in the Settings tab in Application Management for your registered app, make sure you have put in a valid callback URL (it cannot just be localhost, etc) but do not check the `Enable Callback Locking` box. Leaving this unchecked will allow you to use your localhostaddress the app is currently running on as a callback URL that is specified/included in the signature creation process and inital Authorization Header reqeust to get the request token. 

TO RUN USING Gunicorn:

`$ gunicorn views:app -p views.txt -b localhost:8000`


