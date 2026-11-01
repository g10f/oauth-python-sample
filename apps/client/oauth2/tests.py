"""
This file demonstrates writing tests using the unittest module. These will pass
when you run "manage.py test".

Replace this with more appropriate tests for your application.
"""
import json
import time
from unittest import mock
from urllib.parse import urlsplit, parse_qs

from django.contrib.auth import get_user_model
from django.test import TestCase, Client as TestClient
from django.urls import reverse
from django.utils.timezone import now, timedelta

from client.oauth2.backend import refresh_access_token
from client.oauth2.crypt import _json_encode, _urlsafe_b64encode, _urlsafe_b64decode
from client.oauth2.models import IdentityProvider, Client, AccessToken, RefreshToken


def get_state_from_uri(uri):
    return parse_qs(urlsplit(uri).query)['state'][0]


def change_state(state, **changes):
    data = json.loads(_urlsafe_b64decode(state).decode('utf-8'))
    data.update(changes)
    return encode_state(data)


def encode_state(data):
    return _urlsafe_b64encode(_json_encode(data).encode('ascii')).decode('ascii')


class OAuth2Tests(TestCase):

    def test_login_view_with_error_code(self):
        response = self.client.get(reverse('login') + "?error=testerror")
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "testerror")


class RefreshTokenTests(TestCase):

    def test_tokens_are_not_logged(self):
        identity_provider = IdentityProvider.objects.create(
            name='Test IdP', issuer='https://idp.example.com', authorization_endpoint='https://idp.example.com/auth',
            token_endpoint='https://idp.example.com/token')
        client = Client.objects.create(identity_provider=identity_provider, client_id='test-client')
        user = get_user_model().objects.create(username='user')
        access_token = AccessToken.objects.create(client=client, user=user, token='old-access-token',
                                                  expires_at=now())
        RefreshToken.objects.create(access_token=access_token, token='old-refresh-token')

        response = mock.Mock(status_code=200, headers={'content-type': 'application/json'})
        response.json.return_value = {'access_token': 'new-access-token', 'refresh_token': 'new-refresh-token',
                                      'id_token': 'new-id-token', 'expires_in': 3600, 'scope': 'openid'}
        with mock.patch('client.oauth2.backend.requests.post', return_value=response):
            with self.assertLogs('client.oauth2.backend', level='DEBUG') as logs:
                new_access_token = refresh_access_token(access_token, user)

        self.assertEqual(new_access_token.token, 'new-access-token')
        output = '\n'.join(logs.output)
        self.assertIn('expires_in=3600', output)
        self.assertNotIn('new-access-token', output)
        self.assertNotIn('new-refresh-token', output)
        self.assertNotIn('new-id-token', output)


class StateTests(TestCase):
    """
    The state of the authorization request is only accepted from the browser it was created for and its next url
    must point to this site.
    """

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

    def test_state_of_the_same_browser_is_accepted(self):
        state = self.get_state(self.client)
        response = self.callback(self.client, state)
        self.assertEqual(response.status_code, 302)
        self.assertIn('_auth_user_id', self.client.session)

    def test_state_of_another_browser_is_rejected(self):
        attacker = TestClient()
        state = self.get_state(attacker)
        self.get_state(self.client)  # the victim has a session with its own binding
        response = self.callback(self.client, state)
        self.assertContains(response, 'invalid_state')
        self.assertNotIn('_auth_user_id', self.client.session)

    def test_state_without_session_is_rejected(self):
        state = self.get_state(TestClient())
        response = self.callback(self.client, state)
        self.assertContains(response, 'invalid_state')
        self.assertNotIn('_auth_user_id', self.client.session)

    def test_next_url_of_another_host_is_not_used(self):
        state = change_state(self.get_state(self.client), next='https://evil.example.com/')
        response = self.client.get(reverse('login'), {'state': state})
        self.assertRedirects(response, reverse('login'), fetch_redirect_response=False)

    def test_next_url_of_this_host_is_used(self):
        state = change_state(self.get_state(self.client), next='/oauth2/userinfo/me/')
        response = self.client.get(reverse('login'), {'state': state})
        self.assertRedirects(response, '/oauth2/userinfo/me/', fetch_redirect_response=False)

    def test_next_url_of_another_host_is_not_used_after_the_login(self):
        state = change_state(self.get_state(self.client), next='https://evil.example.com/')
        response = self.callback(self.client, state)
        self.assertRedirects(response, reverse('login'), fetch_redirect_response=False)
        self.assertIn('_auth_user_id', self.client.session)

    def test_next_url_of_wrong_type_is_not_used(self):
        for next_url in (5, ['/'], {'a': 1}):
            with self.subTest(next_url=next_url):
                state = change_state(self.get_state(self.client), next=next_url)
                response = self.callback(self.client, state)
                self.assertRedirects(response, reverse('login'), fetch_redirect_response=False)

    def test_state_without_next_url_redirects_to_the_default(self):
        state = change_state(self.get_state(self.client), next=None)
        response = self.callback(self.client, state)
        self.assertRedirects(response, reverse('login'), fetch_redirect_response=False)
        self.assertIn('_auth_user_id', self.client.session)

    def test_state_without_client_id_logs_in(self):
        state = change_state(self.get_state(self.client), client_id=None)
        response = self.callback(self.client, state)
        self.assertEqual(response.status_code, 302)
        self.assertEqual(self.client.session['client_id'], self.oauth2_client.id)

    def test_state_that_is_no_json_object_is_rejected(self):
        for data in ([], 5, 'text', None):
            with self.subTest(data=data):
                response = self.callback(self.client, encode_state(data))
                self.assertContains(response, 'invalid_state')

    def test_state_with_invalid_nonce_or_client_is_rejected(self):
        invalid_values = ({'nonce': ['x']}, {'nonce': 'a\x00b'}, {'nonce': 5}, {'nonce': None},
                          {'client': 'x'}, {'client': [1]}, {'client': None}, {'client': 10 ** 30})
        for changes in invalid_values:
            with self.subTest(changes=changes):
                state = change_state(self.get_state(self.client), **changes)
                response = self.callback(self.client, state)
                self.assertContains(response, 'invalid_state')
                self.assertNotIn('_auth_user_id', self.client.session)

    def test_code_without_state_is_rejected(self):
        response = self.client.get(reverse('login'), {'code': 'code'})
        self.assertContains(response, 'invalid_state')

    def test_pkce_state_without_valid_code_verifier_is_rejected(self):
        self.oauth2_client.use_pkce = True
        self.oauth2_client.save()
        for code_verifier in (None, 'x', [1], 10 ** 30):
            with self.subTest(code_verifier=code_verifier):
                state = change_state(self.get_state(self.client), code_verifier=code_verifier)
                response = self.callback(self.client, state)
                self.assertContains(response, 'invalid_state')
                self.assertNotIn('_auth_user_id', self.client.session)

    def test_user_name_in_welcome_message_is_escaped(self):
        state = self.get_state(self.client)
        self.callback(self.client, state, name='<script>alert(1)</script>')
        response = self.client.get(reverse('login'))
        self.assertNotContains(response, '<script>alert(1)</script>')
        self.assertContains(response, '&lt;script&gt;alert(1)&lt;/script&gt;')
