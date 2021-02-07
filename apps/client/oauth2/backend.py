import json
import logging
from base64 import b64encode
from json import JSONDecodeError
from urllib.parse import urlsplit, parse_qsl, urlunsplit

import requests
from jwt import decode, InvalidSignatureError
from jwt.algorithms import get_default_algorithms, RSAAlgorithm, HMACAlgorithm

from client.oauth2.logging import debug_requests
from client.oauth2.models import update_user, AccessToken, IdToken, RefreshToken
from client.oauth2.utils import OAuth2Error
from django.conf import settings
from django.contrib.auth.backends import ModelBackend
from django.http import QueryDict
from django.utils import timezone
from django.utils.timezone import now

logger = logging.getLogger(__name__)


def update_url(url, params):
    """Given a URL, add or update query parameter and return the
    modified URL.

    >>> update_url('http://example.com?foo=bar&biz=baz', {'foo': 'stuff', 'new': 'val'})
    'http://example.com?foo=stuff&biz=baz&new=val'

    """
    (scheme, netloc, path, query, fragment) = urlsplit(url)
    q = QueryDict(query, mutable=True)

    for k, v in params.items():
        if v is not None:  # filter out None values
            q[k] = v

    new_query_string = q.urlencode(safe='/')
    return urlunsplit((scheme, netloc, path, new_query_string, fragment))


def replace_or_add_query_param(url, attr, val):
    (scheme, netloc, path, query, fragment) = urlsplit(url)
    query_dict = QueryDict(query).copy()
    query_dict[attr] = val
    query = query_dict.urlencode()
    return urlunsplit((scheme, netloc, path, query, fragment))


def url_update(url, param_dict):
    (scheme, netloc, path, query, fragment) = urlsplit(url)
    query_dict = QueryDict(query).copy()
    for key, value in param_dict.items():
        if value is not None:
            query_dict[key] = value
    query = query_dict.urlencode()
    return urlunsplit((scheme, netloc, path, query, fragment))


def decode_idp_jwt_token(client, token, **kwargs):
    # Don't need to verify with certs, because we got the id_token directly from the id_provider via ssl
    options = {
        'verify_exp': True,
        'verify_nbf': True,
        'verify_iat': True,
        'verify_aud': True,
        'require_exp': True,
        'require_iat': True,
        'require_nbf': False
    }
    options.update(kwargs)
    if client.identity_provider.jwks_uri:
        options['verify_signature'] = True
        jwks = client.identity_provider.jwks
        token_content = None
        for jwk in jwks:
            if jwk['kty'] == 'RSA':
                key = RSAAlgorithm.from_jwk(json.dumps(jwk))
            elif jwk['kty'] == 'oct':
                key = HMACAlgorithm.from_jwk(json.dumps(jwk))
            else:
                raise OAuth2Error('kty %s is not supported' % jwk['kty'], 'invalid_kty')
            try:
                token_content = decode(token, key=key, audience=client.client_id, options=options,
                                       algorithms=get_default_algorithms())
                break
            except InvalidSignatureError:
                pass
        if token_content is None:
            raise InvalidSignatureError()
    else:
        options['verify_signature'] = False
        token_content = decode(token, audience=client.client_id, options=options,
                               algorithms=get_default_algorithms())
    return options, token_content


def get_tokens_from_code(client, code, code_verifier, redirect_uri):
    headers = {'content-type': 'application/x-www-form-urlencoded', 'Accept': 'application/json'}
    query = {
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': redirect_uri
    }
    if client.use_pkce:
        query['code_verifier'] = '%s' % code_verifier
    if client.client_secret:
        auth = b"%s:%s" % (client.client_id.encode(), client.client_secret.encode())
        headers['authorization'] = '%s %s' % ('Basic', b64encode(auth).decode("ascii"))
    else:
        query['client_id'] = client.client_id

    if settings.DEBUG_REQUESTS:
        with debug_requests():
            r = requests.post(client.identity_provider.token_endpoint, data=query, headers=headers,
                              verify=client.identity_provider.is_secure)
    else:
        r = requests.post(client.identity_provider.token_endpoint, data=query, headers=headers,
                          verify=client.identity_provider.is_secure)

    if r.status_code >= 400:
        raise OAuth2Error(r.text, r.status_code)

    content_type = r.headers.get('content-type', '').split(';')[0]

    try:
        if content_type == "text/plain":  # facebook returns the data as text
            content = dict(parse_qsl(r.text))
        else:
            content = r.json()

        if content.get('error'):
            message = content.get('error_description')
            error = content.get('error')
            raise OAuth2Error(message, error)

    except JSONDecodeError as e:
        logger.error(e)
        raise OAuth2Error('', e)

    expires_in = content.get('expires_in', 3600)  # default 1 hour
    access_token = AccessToken(
        client=client,
        token=content['access_token'],
        type=content.get('token_type', ''),  # facebook is not OAuth2 compliant
        scope=content.get('scope', ''),  # custom optional field
        expires_at=timezone.now() + timezone.timedelta(0, expires_in))

    id_token_content = None
    if 'id_token' in content:
        options, id_token_content = decode_idp_jwt_token(client, content['id_token'])
        id_token_content['raw'] = content['id_token']
        if client.roles_claim and client.roles_claim in id_token_content:
            id_token_content[client.roles_claim] = id_token_content[client.roles_claim].split()

    refresh_token = None
    if 'refresh_token' in content:
        refresh_token = RefreshToken(token=content['refresh_token'])

    return access_token, id_token_content, refresh_token


def refresh_access_token(access_token, user):
    client = access_token.client
    refresh_token = access_token.refresh_token
    query = {
        'grant_type': 'refresh_token',
        'client_id': client.client_id,
        'client_secret': client.client_secret,
        'refresh_token': refresh_token
    }

    # body = urlencode(query)
    r = requests.post(client.identity_provider.token_endpoint, data=query,
                      headers={'content-type': 'application/x-www-form-urlencoded',
                               'Accept': 'application/json'})
    if r.status_code >= 400:
        raise OAuth2Error(r.text, r.status_code)

    content_type = r.headers.get('content-type', '').split(';')[0]

    try:
        if content_type == "text/plain":  # facebook returns the data as text
            content = dict(parse_qsl(r.text))
        else:
            content = r.json()

        logger.info(json.dumps(content, indent=4, sort_keys=True))
        if content.get('error'):
            message = content.get('error_description')
            error = content.get('error')
            raise OAuth2Error(message, error)

    except JSONDecodeError as e:
        logger.error(e)
        raise OAuth2Error('', e)

    expires_in = content.get('expires_in', 3600)
    access_token = AccessToken.objects.create(
        user=user,
        client=client,
        token=content['access_token'],
        type=content.get('token_type', ''),  # facebook is not OAuth2 compliant
        scope=content.get('scope', ''),  # custom optional field
        expires_at=timezone.now() + timezone.timedelta(0, expires_in))

    if 'refresh_token' in content:
        RefreshToken.objects.create(access_token=access_token, token=content['refresh_token'])
    else:  # use the old one
        RefreshToken.objects.create(access_token=access_token, token=refresh_token)

    return access_token


def get_access_token(user):
    access_token = AccessToken.objects.filter(user=user).latest()
    if access_token.expires_at <= now() and hasattr(access_token, 'refresh_token'):
        access_token = refresh_access_token(access_token, user)
    else:
        logger.warning('Access Token expired and we have no refresh token.')

    return access_token


def get_userinfo(access_token, uuid=None):
    identity_provider = access_token.client.identity_provider
    userinfo_endpoint = identity_provider.userinfo_endpoint
    if not userinfo_endpoint:
        raise OAuth2Error("no userinfo endpoint configured", "no_userinfo_endpoint")

    if uuid:
        userinfo_endpoint = userinfo_endpoint.replace('me', uuid)

    # with microsoft deflate, zlib.decompress gives an error "unknown compression" ?
    headers = {'accept': 'application/json',
               'accept-encoding': 'gzip'}

    if not identity_provider.is_supporting_http_auth_header:
        # access_token as HTTP GET parameter
        userinfo_endpoint = url_update(userinfo_endpoint, {'access_token': access_token.token})
    else:
        headers['authorization'] = '%s %s' % (access_token.type, access_token.token)

    r = requests.get(userinfo_endpoint, headers=headers, verify=identity_provider.is_secure)

    return r.json()


class OAuth2Backend(ModelBackend):
    def authenticate(self, request, client=None, code=None, redirect_uri=None, session_state=None, code_verifier=None,
                     **kwargs):
        if not code:
            return None

        access_token, id_token_content, refresh_token = get_tokens_from_code(client, code, code_verifier, redirect_uri)
        """
        You can use the OpenID Connect id_token which contains the userid and email
        or make another request (GET ../userinfo/ ) to get the userinfos 
        """

        # TODO: update user from get_userinfo 
        if id_token_content:  # and 'name' in id_token_content:
            userinfo = id_token_content
        else:
            userinfo = get_userinfo(access_token)
        user = update_user(client, userinfo)

        """
        Save the tokens in the database for reusing
        """
        access_token.user = user
        access_token.save()

        if id_token_content:
            id_token = IdToken.create_from_token(id_token_content, client)
            id_token.user = user
            id_token.session_state = session_state
            id_token.save()

        if refresh_token:
            refresh_token.access_token = access_token
            refresh_token.save()
        return user
