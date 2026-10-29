"""
This file demonstrates writing tests using the unittest module. These will pass
when you run "manage.py test".

Replace this with more appropriate tests for your application.
"""
import time
from unittest import mock
from urllib.parse import urlsplit, parse_qs

from django.test import TestCase
from django.urls import reverse
from django.utils.timezone import now, timedelta

from client.oauth2.models import IdentityProvider, Client, AccessToken


def get_state_from_uri(uri):
    return parse_qs(urlsplit(uri).query)['state'][0]


class OAuth2Tests(TestCase):

    def test_login_view_with_error_code(self):
        response = self.client.get(reverse('login') + "?error=testerror")
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "testerror")


class LoginTests(TestCase):

    def setUp(self):
        self.identity_provider = IdentityProvider.objects.create(
            name='Test IdP', issuer='https://idp.example.com', authorization_endpoint='https://idp.example.com/auth',
            token_endpoint='https://idp.example.com/token')
        self.oauth2_client = Client.objects.create(identity_provider=self.identity_provider, client_id='test-client')

    def get_state(self, browser):
        # the login page renders a login link with a new state for every client
        response = browser.get(reverse('login'))
        return get_state_from_uri(response.context['authentications'][0]['uri'])

    def callback(self, browser, state, name='Test User'):
        """
        The redirect from the identity provider back to the login view, without the token request to the
        identity provider.
        """
        access_token = AccessToken(client=self.oauth2_client, token='access-token',
                                   expires_at=now() + timedelta(hours=1))
        id_token_content = {'sub': 'user-1', 'name': name, 'aud': 'test-client', 'iss': 'https://idp.example.com',
                            'iat': int(time.time()), 'exp': int(time.time()) + 3600, 'raw': 'raw-id-token'}
        with mock.patch('client.oauth2.backend.get_tokens_from_code',
                        return_value=(access_token, id_token_content, None)):
            return browser.get(reverse('login'), {'state': state, 'code': 'code'})

    def test_user_name_in_welcome_message_is_escaped(self):
        state = self.get_state(self.client)
        self.callback(self.client, state, name='<script>alert(1)</script>')
        response = self.client.get(reverse('login'))
        self.assertNotContains(response, '<script>alert(1)</script>')
        self.assertContains(response, '&lt;script&gt;alert(1)&lt;/script&gt;')
