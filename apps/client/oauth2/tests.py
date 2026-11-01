import json
import time
import warnings
from unittest import mock
from urllib.parse import urlsplit, parse_qs

import jwt
import requests
from cryptography.hazmat.primitives.asymmetric import rsa
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.core.cache.backends.base import CacheKeyWarning
from django.test import TestCase, Client as TestClient
from django.urls import reverse
from django.utils.text import slugify
from django.utils.timezone import now, timedelta
from jwt.algorithms import RSAAlgorithm

from client.oauth2.backend import get_tokens_from_code, get_userinfo, refresh_access_token, replace_me_in_path
from client.oauth2.crypt import _json_encode, _urlsafe_b64encode, _urlsafe_b64decode
from client.oauth2.middleware import get_user_and_client_from_token, verify_signed_jwt
from client.oauth2.models import ApiClient, IdentityProvider, Client, AccessToken, RefreshToken
from client.oauth2.utils import OAuth2Error


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


def create_identity_provider(name='Test IdP', **kwargs):
    return IdentityProvider.objects.create(
        name=name, issuer=f'https://{slugify(name)}.example.com',
        authorization_endpoint='https://idp.example.com/auth', token_endpoint='https://idp.example.com/token', **kwargs)


def token_response(content):
    response = mock.Mock(status_code=200, headers={'content-type': 'application/json'})
    response.json.return_value = content
    return response


class IdTokenNonceTests(TestCase):

    def setUp(self):
        identity_provider = create_identity_provider()
        self.oauth2_client = Client.objects.create(identity_provider=identity_provider, client_id='test-client')

    def start_login(self, browser):
        uri = browser.get(reverse('login')).context['authentications'][0]['uri']
        query = parse_qs(urlsplit(uri).query)
        return query['state'][0], query['nonce'][0]

    def callback(self, browser, state, nonce):
        """The token response is real, only the signature check of the id token is left out."""
        id_token_content = {'sub': 'user-1', 'name': 'Test User', 'aud': 'test-client',
                            'iss': 'https://idp.example.com', 'iat': int(time.time()),
                            'exp': int(time.time()) + 3600}
        if nonce is not None:
            id_token_content['nonce'] = nonce
        response = token_response({'access_token': 'token', 'id_token': 'id-token'})
        with mock.patch('client.oauth2.backend.requests.post', return_value=response), \
                mock.patch('client.oauth2.backend.decode_idp_jwt_token', return_value=({}, id_token_content)):
            return browser.get(reverse('login'), {'state': state, 'code': 'code'})

    def test_nonce_of_the_authentication_request_is_accepted(self):
        state, nonce = self.start_login(self.client)
        response = self.callback(self.client, state, nonce)
        self.assertEqual(response.status_code, 302)
        self.assertIn('_auth_user_id', self.client.session)

    def test_id_token_without_or_with_wrong_nonce_is_rejected(self):
        for wrong_nonce in (None, 'wrong', 5):
            with self.subTest(nonce=wrong_nonce):
                state, nonce = self.start_login(self.client)
                response = self.callback(self.client, state, wrong_nonce)
                self.assertContains(response, 'invalid_nonce')
                self.assertNotIn('_auth_user_id', self.client.session)

    def test_id_token_of_another_browser_session_is_rejected(self):
        # The attacker injects the code of the victim into his own session, with a state of his own session.
        _, victim_nonce = self.start_login(TestClient())
        attacker_state, _ = self.start_login(self.client)
        response = self.callback(self.client, attacker_state, victim_nonce)
        self.assertContains(response, 'invalid_nonce')
        self.assertNotIn('_auth_user_id', self.client.session)

    def test_nonce_sent_to_the_identity_provider_is_not_the_visible_state_nonce(self):
        state, nonce = self.start_login(self.client)
        self.assertNotEqual(nonce, json.loads(_urlsafe_b64decode(state).decode('utf-8'))['nonce'])

    def test_login_without_id_token_needs_no_nonce(self):
        state, nonce = self.start_login(self.client)
        userinfo = {'sub': 'user-1', 'name': 'Test User'}
        response = token_response({'access_token': 'token'})
        with mock.patch('client.oauth2.backend.requests.post', return_value=response), \
                mock.patch('client.oauth2.backend.get_userinfo', return_value=userinfo), \
                mock.patch('client.oauth2.backend.update_user', return_value=get_user_model().objects.create(
                    username='user', unique_name='user')):
            response = self.client.get(reverse('login'), {'state': state, 'code': 'code'})
        self.assertEqual(response.status_code, 302)


class IdentityProviderRequestTests(TestCase):

    def setUp(self):
        cache.clear()
        self.addCleanup(cache.clear)

    def test_signing_keys_are_cached_per_identity_provider(self):
        first = create_identity_provider('First', jwks_uri='https://first.example.com/jwks')
        second = create_identity_provider('Second', jwks_uri='https://second.example.com/jwks')

        def get_keys(url, **kwargs):
            return token_response({'keys': [{'kid': 'same-kid', 'use': 'sig', 'source': url}]})

        with mock.patch('client.oauth2.models.requests.get', side_effect=get_keys) as get:
            self.assertEqual(first._get_jwks_from_kid('same-kid')['source'], first.jwks_uri)
            self.assertEqual(second._get_jwks_from_kid('same-kid')['source'], second.jwks_uri)
            first._get_jwks_from_kid('same-kid')
        self.assertEqual(get.call_count, 2)
        self.assertIsNotNone(get.call_args.kwargs['timeout'])

    def test_unknown_kid_keeps_line_breaks_out_of_the_error(self):
        identity_provider = create_identity_provider(jwks_uri='https://idp.example.com/jwks')
        with mock.patch('client.oauth2.models.requests.get', return_value=token_response({'keys': []})), \
                self.assertRaises(OAuth2Error) as context, warnings.catch_warnings():
            warnings.simplefilter('error', CacheKeyWarning)
            identity_provider.get_signing_key_from_kid('kid\nforged log line')
        self.assertNotIn('\n', context.exception.message)

    def test_broken_jwks_responses_are_rejected(self):
        identity_provider = create_identity_provider(jwks_uri='https://idp.example.com/jwks')
        kid = {'kid': 'kid', 'use': 'sig'}
        responses = ([], 'text', None, {}, {'keys': None}, {'keys': {}}, {'keys': ['text', 5]}, {'keys': [kid]},
                     {'keys': [{**kid, 'kty': 'unknown'}]}, {'keys': [{**kid, 'kty': 'RSA', 'alg': 'none'}]})
        for content in responses:
            with self.subTest(content=content):
                cache.clear()
                with mock.patch('client.oauth2.models.requests.get', return_value=token_response(content)), \
                        self.assertRaises(OAuth2Error):
                    identity_provider.get_signing_key_from_kid('kid')

    def test_jwks_request_uses_the_tls_setting_of_the_identity_provider(self):
        identity_provider = create_identity_provider(jwks_uri='https://idp.example.com/jwks', is_secure=False)
        response = token_response({'keys': [{'kid': 'kid', 'use': 'sig'}]})
        with mock.patch('client.oauth2.models.requests.get', return_value=response) as get:
            identity_provider._get_jwks_from_kid('kid')
        self.assertIs(get.call_args.kwargs['verify'], False)

    def test_broken_jwks_response_shows_an_error_page_at_login(self):
        identity_provider = create_identity_provider(jwks_uri='https://idp.example.com/jwks')
        Client.objects.create(identity_provider=identity_provider, client_id='test-client')
        uri = self.client.get(reverse('login')).context['authentications'][0]['uri']
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        id_token = jwt.encode({'sub': 'user-1'}, key, algorithm='RS256', headers={'kid': 'key-1'})
        response = token_response({'access_token': 'token', 'id_token': id_token})
        with mock.patch('client.oauth2.backend.requests.post', return_value=response), \
                mock.patch('client.oauth2.models.requests.get', return_value=token_response([])):
            response = self.client.get(reverse('login'), {'state': get_state_from_uri(uri), 'code': 'code'})
        self.assertContains(response, 'signing_error')

    def test_all_requests_have_a_timeout(self):
        identity_provider = create_identity_provider(userinfo_endpoint='https://idp.example.com/userinfo')
        client = Client.objects.create(identity_provider=identity_provider, client_id='test-client')
        user = get_user_model().objects.create(username='user', unique_name='user')
        access_token = AccessToken.objects.create(client=client, user=user, token='token', type='Bearer',
                                                  expires_at=now())
        RefreshToken.objects.create(access_token=access_token, token='refresh-token')
        response = token_response({'access_token': 'token'})
        with mock.patch('client.oauth2.backend.requests.post', return_value=response) as post, \
                mock.patch('client.oauth2.backend.requests.get', return_value=response) as get:
            get_tokens_from_code(client, 'code', None, 'https://example.com/', 'nonce')
            refresh_access_token(access_token, user)
            get_userinfo(access_token)
        for call in post.call_args_list + get.call_args_list:
            self.assertIsNotNone(call.kwargs['timeout'])
            self.assertIn('verify', call.kwargs)

    def test_unreachable_identity_provider_shows_an_error_page(self):
        Client.objects.create(identity_provider=create_identity_provider(), client_id='test-client')
        uri = self.client.get(reverse('login')).context['authentications'][0]['uri']
        with mock.patch('client.oauth2.backend.requests.post', side_effect=requests.Timeout('secret-url')):
            response = self.client.get(reverse('login'), {'state': get_state_from_uri(uri), 'code': 'code'})
        self.assertContains(response, 'temporarily_unavailable')
        self.assertNotContains(response, 'secret-url')

    def test_only_the_path_segment_me_is_replaced(self):
        self.assertEqual(replace_me_in_path('https://me.example.com/name/users/me/?some=me', '123'),
                         'https://me.example.com/name/users/123/?some=me')


class SignedJwtTests(TestCase):
    """Access tokens of the api, signed by the identity provider."""

    def setUp(self):
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.identity_provider = create_identity_provider(jwks_uri='https://idp.example.com/jwks')
        ApiClient.objects.create(identity_provider=self.identity_provider, client_id='api-client')
        public_jwk = json.loads(RSAAlgorithm.to_jwk(self.private_key.public_key()))
        public_jwk.update({'kid': 'key-1', 'use': 'sig'})
        patcher = mock.patch.object(IdentityProvider, '_get_jwks_from_kid', return_value=public_jwk)
        patcher.start()
        self.addCleanup(patcher.stop)

    def token(self, key=None, algorithm='RS256', headers=None, **changes):
        payload = {'iss': self.identity_provider.issuer, 'aud': 'api-client', 'sub': 'user-1', 'scope': 'read',
                   'exp': int(time.time()) + 3600}
        payload.update(changes)
        payload = {name: value for name, value in payload.items() if value is not None}
        return jwt.encode(payload, key or self.private_key, algorithm=algorithm, headers=headers or {'kid': 'key-1'})

    def test_valid_token_is_accepted(self):
        user, client, scopes = get_user_and_client_from_token(self.token())
        self.assertEqual(user.uuid, 'user-1')
        self.assertEqual(client.client_id, 'api-client')
        self.assertEqual(scopes, {'read'})

    def test_invalid_tokens_are_rejected(self):
        other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        tokens = {
            'other key': self.token(key=other_key),
            'expired': self.token(exp=int(time.time()) - 3600),
            'unknown client': self.token(aud='other-client'),
            'no audience': self.token(aud=None),
            'no issuer': self.token(iss=None),
            'no expiry': self.token(exp=None),
            'no subject': self.token(sub=None),
            'issuer with nul byte': self.token(iss='https://idp\x00.example.com'),
            'issuer of wrong type': jwt.PyJWS().encode(
                json.dumps({'iss': ['https://idp.example.com'], 'aud': 'api-client', 'sub': 'user-1'}).encode(),
                self.private_key, algorithm='RS256', headers={'kid': 'key-1'}),
            'unknown issuer': self.token(iss='https://other.example.com'),
            'symmetric algorithm': self.token(key='a' * 64, algorithm='HS256'),
            'no jwt': 'no-jwt',
        }
        for name, token in tokens.items():
            with self.subTest(name):
                user, client, scopes = get_user_and_client_from_token(token)
                self.assertFalse(user.is_authenticated)
                self.assertIsNone(client)

    def test_issuer_with_nul_byte_does_not_reach_the_database(self):
        # SQLite accepts the value, PostgreSQL would answer with an error and the request would end as a server error.
        with self.assertNumQueries(0), self.assertRaises(jwt.InvalidIssuerError):
            verify_signed_jwt(self.token(iss='https://idp\x00.example.com'))

    def test_token_of_an_unknown_client_creates_no_user(self):
        get_user_and_client_from_token(self.token(aud='other-client'))
        self.assertFalse(get_user_model().objects.exists())


class ErrorOutputTests(TestCase):

    def setUp(self):
        self.user = get_user_model().objects.create(username='user', unique_name='user',
                                                    identity_provider=create_identity_provider())
        self.client.force_login(self.user)

    def test_errors_are_escaped(self):
        error = OAuth2Error('<script>alert(1)</script>', 'error')
        for name in ('userinfo_me', 'tokeninfo_me'):
            with self.subTest(name), mock.patch('client.oauth2.views.get_access_token', side_effect=error):
                response = self.client.get(reverse(name))
                self.assertNotContains(response, '<script>alert(1)</script>')
                self.assertContains(response, '&lt;script&gt;alert(1)&lt;/script&gt;')

    def test_tokeninfo_shows_the_userinfo_error(self):
        client = Client.objects.create(identity_provider=self.user.identity_provider, client_id='test-client')
        access_token = AccessToken(client=client, user=self.user, token='token', expires_at=now())
        with mock.patch('client.oauth2.views.get_access_token', return_value=access_token), \
                mock.patch('client.oauth2.views.decode_idp_jwt_token', return_value=({}, {})), \
                mock.patch('client.oauth2.views.get_userinfo', side_effect=ValueError('<b>userinfo failed</b>')):
            response = self.client.get(reverse('tokeninfo_me'))
        self.assertContains(response, '&lt;b&gt;userinfo failed&lt;/b&gt;')

    def test_failed_request_shows_no_url_with_access_token(self):
        client = Client.objects.create(identity_provider=self.user.identity_provider, client_id='test-client')
        access_token = AccessToken(client=client, user=self.user, token='token', expires_at=now())
        error = requests.ConnectionError('https://idp.example.com/userinfo?access_token=secret-token')
        for name in ('userinfo_me', 'tokeninfo_me'):
            with self.subTest(name), self.assertLogs('client.oauth2.views', level='INFO') as logs, \
                    mock.patch('client.oauth2.views.get_access_token', return_value=access_token), \
                    mock.patch('client.oauth2.views.decode_idp_jwt_token', return_value=({}, {})), \
                    mock.patch('client.oauth2.views.get_userinfo', side_effect=error):
                response = self.client.get(reverse(name))
                self.assertContains(response, "can&#x27;t be reached")
                self.assertNotContains(response, 'secret-token')
                self.assertNotIn('secret-token', '\n'.join(logs.output))

    def test_failed_request_logs_the_host_and_type(self):
        client = Client.objects.create(identity_provider=self.user.identity_provider, client_id='test-client')
        access_token = AccessToken(client=client, user=self.user, token='token', expires_at=now())
        url = 'https://idp.example.com/userinfo?access_token=secret-token'
        error = requests.exceptions.SSLError(url, request=requests.Request('GET', url).prepare())
        with self.assertLogs('client.oauth2.views', level='INFO') as logs, \
                mock.patch('client.oauth2.views.get_access_token', return_value=access_token), \
                mock.patch('client.oauth2.views.get_userinfo', side_effect=error):
            self.client.get(reverse('userinfo_me'))
        output = '\n'.join(logs.output)
        self.assertIn('The request to idp.example.com failed: SSLError', output)
        self.assertNotIn('secret-token', output)

    def test_only_web_urls_of_applications_are_links(self):
        client = Client.objects.create(identity_provider=self.user.identity_provider, client_id='test-client')
        access_token = AccessToken(client=client, user=self.user, token='token', expires_at=now())
        userinfo = {'applications': {
            'a': {'links': {'app': {'href': 'https://app.example.com/', 'title': 'Web'}}},
            'b': {'links': {'app': {'href': 'javascript:alert(1)', 'title': 'Script'}}},
        }}
        with mock.patch('client.oauth2.views.get_access_token', return_value=access_token), \
                mock.patch('client.oauth2.views.get_userinfo', return_value=userinfo):
            response = self.client.get(reverse('userinfo_me'))
        self.assertContains(response, 'href="https://app.example.com/"')
        self.assertContains(response, 'Script')
        self.assertNotContains(response, 'javascript:alert(1)')


class RefreshTokenTests(TestCase):

    def test_tokens_are_not_logged(self):
        client = Client.objects.create(identity_provider=create_identity_provider(), client_id='test-client')
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
        self.identity_provider = create_identity_provider()
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

    def test_session_binding_does_not_leave_the_session(self):
        uri = self.client.get(reverse('login')).context['authentications'][0]['uri']
        session_binding = self.client.session['oauth2_state_binding']
        query = parse_qs(urlsplit(uri).query)
        state = json.loads(_urlsafe_b64decode(query['state'][0]).decode('utf-8'))
        self.assertNotIn(session_binding, uri)
        self.assertNotIn(session_binding, json.dumps(state))
        self.assertNotEqual(state['binding'], query['nonce'][0])

    def test_leaked_state_does_not_help_to_attack_the_victim(self):
        # The attacker knows an older state of the victim and takes a new nonce from his own login page.
        leaked_state = self.get_state(self.client)
        attacker_state = self.get_state(TestClient())
        attacker_nonce = json.loads(_urlsafe_b64decode(attacker_state).decode('utf-8'))['nonce']
        response = self.callback(self.client, change_state(leaked_state, nonce=attacker_nonce))
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

    def test_state_with_lone_surrogates_is_rejected(self):
        for field in ('binding', 'next', 'other'):
            for query in ({}, {'code': 'code'}):
                with self.subTest(field=field, query=query):
                    data = json.loads(_urlsafe_b64decode(self.get_state(self.client)).decode('utf-8'))
                    data[field] = '/\ud800'
                    state = _urlsafe_b64encode(json.dumps(data).encode('ascii')).decode('ascii')
                    response = self.client.get(reverse('login'), {'state': state, **query})
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
