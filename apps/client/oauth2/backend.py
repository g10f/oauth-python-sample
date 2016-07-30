# -*- coding: utf-8 -*-
import json
import logging

import httplib2
from django.conf import settings
from django.contrib.auth.backends import ModelBackend
from django.http import QueryDict
from django.utils import timezone
from django.utils.http import urlencode
from django.utils.six.moves.urllib.parse import urlsplit, parse_qsl, urlunsplit
from django.utils.timezone import now

from client.oauth2.crypt import verify_signed_jwt_with_certs
from client.oauth2.models import update_user, AccessToken, IdToken, RefreshToken

logger = logging.getLogger(__name__)


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


class OAuth2Error(Exception):
    error = {'error': None}

    def __init__(self, error, description=None, state=None):
        self.error = error
        self.description = description
        self.state = state

    def __unicode__(self):
        return u'error: %s, description: %s' % (self.error, self.description)


def get_tokens_from_code(client, code, redirect_uri, http=None):
    query = {
        'grant_type': 'authorization_code',
        'client_id': client.client_id,
        'client_secret': client.client_secret,
        'code': code,
        'redirect_uri': redirect_uri
    }

    body = urlencode(query)
    if not http:
        http = httplib2.Http(disable_ssl_certificate_validation=settings.DISABLE_SSL_CERTIFICATE_VALIDATION)

    response, content = http.request(client.identity_provider.token_endpoint, method='POST', body=body, 
                                     headers={'content-type': 'application/x-www-form-urlencoded',
                                              'Accept': 'application/json'})
    content = content.decode("utf-8")
    content_type = response.get('content-type', '').split(';')[0]

    if content_type == "text/plain":  # facebook returns the data as text
        content = dict(parse_qsl(content))
    else:
        content = json.loads(content)

    if content.get('error'):
        description = content.get('error_description')
        error = content.get('error')
        raise OAuth2Error(error, description)
    
    expires_in = content.get('expires_in', 3600)  # default 1 hour
    access_token = AccessToken(
        client=client,
        token=content['access_token'], 
        type=content.get('token_type', ''),  # facebook is not OAuth2 compliant
        scope=content.get('scope', ''),  # custom optional field
        expires_at=timezone.now() + timezone.timedelta(0, expires_in))

    id_token_content = None
    if 'id_token' in content:
        # Don't need to verify with certs, because we got the id_token directly from the id_provider via ssl
        id_token_content = verify_signed_jwt_with_certs(content['id_token'], certs=client.identity_provider.certs, audience=client.client_id)
        id_token_content['raw'] = content['id_token']
        if 'roles' in id_token_content:
            id_token_content['roles'] = id_token_content['roles'].split()

    refresh_token = None
    if 'refresh_token' in content:
        refresh_token = RefreshToken(token=content['refresh_token'])

    return access_token, id_token_content, refresh_token


def refresh_access_token(access_token, http=None):
    client = access_token.client
    query = {
        'grant_type': 'refresh_token',
        'client_id': client.client_id,
        'client_secret': client.client_secret,
        'refresh_token': access_token.refresh_token
    }

    body = urlencode(query)
    if not http:
        http = httplib2.Http(disable_ssl_certificate_validation=settings.DISABLE_SSL_CERTIFICATE_VALIDATION)
    response, content = http.request(client.identity_provider.token_endpoint, method='POST', body=body, 
                                     headers={'content-type': 'application/x-www-form-urlencoded',
                                              'Accept': 'application/json'})
    
    content_type = response.get('content-type', '').split(';')[0]

    if content_type == "text/plain":  # facebook returns the data as text
        content = dict(parse_qsl(content))
    else:
        content = json.loads(content)

    if content.get('error'):
        description = content.get('error_description')
        error = content.get('error')
        raise OAuth2Error(error, description)

    expires_in = content.get('expires_in', 3600) 
    access_token.token = content['access_token']
    access_token.type = content.get('token_type', '')  # facebook is not OAuth2 compliant
    access_token.scope = content.get('scope', '')  # custom optional field
    access_token.expires_at = timezone.now() + timezone.timedelta(0, expires_in)
    access_token.save()

    return access_token


def get_access_token(user):
    access_token = AccessToken.objects.filter(user=user).latest()
    if access_token.expires_at <= now():
        access_token = refresh_access_token(access_token)
    
    return access_token


def get_userinfo(access_token, uuid=None, http=None):
    identity_provider = access_token.client.identity_provider
    userinfo_endpoint = identity_provider.userinfo_endpoint
    if uuid:
        userinfo_endpoint = userinfo_endpoint.replace('me', uuid)
    
    headers = {'accept': 'application/json',
               'accept-encoding': 'gzip'}  # with microsoft deflate, zlib.decompress gives an error "unknown compression" ?
    
    if not identity_provider.is_supporting_http_auth_header:
        # access_token as HTTP GET parameter
        userinfo_endpoint = url_update(userinfo_endpoint, {'access_token': access_token.token})
    else:
        headers['authorization'] = '%s %s' % (access_token.type, access_token.token)
    
    if not http:
        http = httplib2.Http(disable_ssl_certificate_validation=settings.DISABLE_SSL_CERTIFICATE_VALIDATION)
    resp, content = http.request(userinfo_endpoint, headers=headers)
        
    if resp.status != 200:
        raise OAuth2Error("invalid_response", resp)
    
    userinfo = json.loads(content.decode('utf-8'))
    return userinfo


class OAuth2Backend(ModelBackend):
    def authenticate(self, client=None, code=None, redirect_uri=None, session_state=None, **kwargs):
        if not code:
            return None
        
        http = httplib2.Http(disable_ssl_certificate_validation=settings.DISABLE_SSL_CERTIFICATE_VALIDATION)
        access_token, id_token_content, refresh_token = get_tokens_from_code(client, code, redirect_uri, http)
        """
        You can use the OpenID Connect id_token which contains the userid and email
        or make another request (GET ../userinfo/ ) to get the userinfos 
        """ 
        
        # TODO: update user from get_userinfo 
        if id_token_content and 'name' in id_token_content:
            userinfo = id_token_content
        else:
            userinfo = get_userinfo(access_token, http=http)
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
