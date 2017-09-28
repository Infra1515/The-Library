from rauth import OAuth2Service
from flask import current_app, url_for, request, redirect, session
import json
from urllib.request import urlopen
import codecs



class OAuthSignIn(object):
    """ Simple abstraction layer on top of rauth so that the code can be used
    generically without being tied to a specific provider configuration.
    Contains methods and events that are common to all OAuth providers.
    The OAuthSignIn base class defines the structure that the subclasses
    that implement each provider must follow
    """
    providers = None

    def __init__(self, provider_name):
        """
        Constructor method of the class. Initializes provider's name,
        application id and secret assigned by it, which are stored in the
        configuration file.
        """
        self.provider_name = provider_name
        credentials = current_app.config['OAUTH_CREDENTIALS'][provider_name]
        self.consumer_id = credentials['id']
        self.consumer_secret = credentials['secret']

    def authorize(self):
        """ Initiation of the authentication process. The application needs
        to redirect to the provider website and let the user authenticate there
        """
        pass

    def callback(self):
        """ Once the authentication is completed, the provider
        redirects back to the application.
        This is handled by the callback() method.
        """
        pass

    def get_callback_url(self):
        """ Returns the URL that the provider needs to redirect to.
        It is  build using the provider name, so each provider has a dedicated
        route in the views functions
        """
        return url_for('auth.oauth_callback', provider = self.provider_name,
                        _external = True)
    @classmethod
    def get_provider(self, provider_name):
        """
        The get_provider() class method is used to lookup the correct
        OAuthSignIn instance given a provider name.
        This method uses introspection to find all the OAuthSignIn subclasses,
        and then saves an instance of each in a dictionary.
        """
        if self.providers is None:
            self.providers = {}
            for provider_class in self.__subclasses__():
                provider = provider_class()
                self.providers[provider.provider_name] = provider
        return self.providers[provider_name]
        # If NoneType error : some function does not return something
        # or the return statement is not reached !!

class FaceBookSignIn(OAuthSignIn):
    """ Class which implements the OAuth process specific to Facebook API.
        Inherits from base class.
    """
    def __init__(self):
        """ Constructor method. Inherits from the base constructor method and
        initializes it with the provider name. Polls the config for settings.

        Service object is set to a an instance of the OAuth2Service class.
        name is the name of the provider, client_id, client_secret are the ones
        assigned in the Facebook API(and in config).

        The authorize_url and access_token_url are URLs defined by Facebook
        for applications to connect to during the authentication process.
        The base_url sets the prefix URL for any Facebook API calls once
        the authentication is complete.
        """
        super(FaceBookSignIn, self).__init__('facebook')
        self.service = OAuth2Service(
            name = 'facebook',
            client_id = self.consumer_id,
            client_secret = self.consumer_secret,
            authorize_url = 'https://graph.facebook.com/oauth/authorize',
            access_token_url = 'https://graph.facebook.com/oauth/access_token',
            base_url = 'https://graph.facebook.com/'
        )

    def authorize(self):
        return redirect(self.service.get_authorize_url(
            scope = 'email', # requests the user email from Facebook
            response_type = 'code', # tells FB that it is a web app
            redirect_uri = self.get_callback_url()) # application route that
                                                    # provider needs to invoke
                                                    # after authentication
        )

    def callback(self):
        """
        In the callback() method the provider passes a verification token
        that the application can use to contact the provider's APIs.
        """
        def decode_json(payload):
            """ Function to decode the token. FB API returns JSON,
            rauth expects the token in the query string of the request
            """
            return json.loads(payload.decode('utf-8'))

        if 'code' not in request.args:
            return None, None, None

        # oauth_session object is used to make API calls to the provider.
        oauth_session = self.service.get_auth_session(
            data = {'code': request.args['code'],
                    'grant_type' : 'authorization_code',
                    'redirect_uri' : self.get_callback_url()},
            decoder = decode_json
        )

        me = oauth_session.get('me?fields=id,email').json()

        return (
            # FB exposes user id and email but does not give usernames. So,
            # the username for the app is constructed from the left portion
            # of the  email adress
            me['id'],
            me.get('email').split('@')[0],
            me.get('email')
        )


class GoogleSignIn(OAuthSignIn):
    """ Class that impelemts GoogleOAuth2 authentication.
    Simmilar to FB API but does not require social_id.
    """

    def __init__(self):
        """ Constructor method. Polls directly from google openid
        config for up-to-date info
        """
        super(GoogleSignIn, self).__init__('google')
        googleinfo = urlopen('https://accounts.google.com/.well-known/openid-configuration')
        reader = codecs.getreader("utf-8") # decodes the JSON
        google_params = json.load(reader(googleinfo))
        self.service = OAuth2Service(
                name='google',
                client_id=self.consumer_id,
                client_secret=self.consumer_secret,
                authorize_url=google_params.get('authorization_endpoint'),
                base_url=google_params.get('userinfo_endpoint'),
                access_token_url=google_params.get('token_endpoint')
        )


    def authorize(self):
        return redirect(self.service.get_authorize_url(
            scope = 'email',
            response_type = 'code',
            redirect_uri = self.get_callback_url()
        ))

    def callback(self):
        def decode_json(payload):
            """ Function to decode the token. FB API returns JSON,
            rauth expects the token in the query string of the request
            """
            return json.loads(payload.decode('utf-8'))

        if 'code' not in request.args:
            return None, None, None

        oauth_session = self.service.get_auth_session(
            data = {'code': request.args['code'],
                    'grant_type' : 'authorization_code',
                    'redirect_uri' : self.get_callback_url()},
                decoder = decode_json
        )

        me = oauth_session.get('').json()

        return (me['name'],
                me['email'])
