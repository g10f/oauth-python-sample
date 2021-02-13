import logging

from django.contrib import auth
from django.contrib.auth import get_user_model
from django.contrib.auth.models import AnonymousUser
from django.core import signing
from django.core.exceptions import ObjectDoesNotExist
from django.http import HttpResponseRedirect
from django.utils.deprecation import MiddlewareMixin
from django.utils.functional import SimpleLazyObject
from jwt import decode, InvalidTokenError
from jwt.api_jwt import decode_complete as decode_token

from client.oauth2.models import ApiClient, IdentityProvider
from client.oauth2.views import get_oauth2_authentication_uri_from_name

logger = logging.getLogger(__name__)


def verify_signed_jwt(jwt):
    decoded = decode_token(jwt, options={"verify_signature": False})
    payload = decoded["payload"]
    issuer = payload['iss']
    audiance = payload['aud']  # this is the id of a client of our api
    kid = decoded['header'].get('kid')
    idp = IdentityProvider.objects.get(issuer=issuer)
    key = idp.get_signing_key_from_kid(kid)
    payload = decode(jwt, key=key, audiance=audiance, options={'verify_signature': True})
    return payload, idp


class IterableLazyObject(SimpleLazyObject):
    def __iter__(self):
        if self._wrapped is None:
            self._setup()
        return self._wrapped.__iter__()


def get_user_and_client_from_token(access_token):
    try:
        if not access_token:
            return AnonymousUser(), None, set()
        data, idp = verify_signed_jwt(access_token)
        defaults = {'unique_name': "%s.%s" % (idp, data['sub'])}
        user = get_user_model().objects.get_or_create(uuid=data['sub'], identity_provider=idp, defaults=defaults)[0]
        client = ApiClient.objects.get(identity_provider=idp, client_id=data['aud'], is_active=True)
        scopes = set()
        if data.get('scope'):
            scopes = set(data['scope'].split())
    except (ObjectDoesNotExist, signing.BadSignature, ValueError, InvalidTokenError) as e:
        logger.exception(e)
        return AnonymousUser(), None, set()
    return user, client, scopes


def get_auth_data(request):
    """
    Look for
    
    1. Authorization Header if path starts with /api/
    2. access_token Parameter if path starts with /api/
    3. Standard django session_id
    
    for authentication information
    
    """
    if not hasattr(request, '_cached_auth_data'):
        if request.path.find('/api/') != -1:
            access_token = None
            http_authorization = request.META.get('HTTP_AUTHORIZATION')
            if http_authorization:
                http_authorization = http_authorization.split()
                if http_authorization[0] == 'Bearer':
                    access_token = http_authorization[1]
            else:
                access_token = request.REQUEST.get('access_token')
            if access_token:
                request._cached_auth_data = get_user_and_client_from_token(access_token)

        if not hasattr(request, '_cached_auth_data'):
            # try django auth session
            request._cached_auth_data = auth.get_user(request), None, set()
    return request._cached_auth_data


class OAuthAuthenticationMiddleware(MiddlewareMixin):
    def process_request(self, request):
        assert hasattr(request,
                       'session'), "The Django authentication middleware requires session middleware to be installed." \
                                   " Edit your MIDDLEWARE_CLASSES setting to insert 'django.contrib.sessions." \
                                   "middleware.SessionMiddleware'."

        request.user = SimpleLazyObject(lambda: get_auth_data(request)[0])
        request.client = SimpleLazyObject(lambda: get_auth_data(request)[1])
        request.scopes = IterableLazyObject(lambda: get_auth_data(request)[2])


class LoginMiddleware(MiddlewareMixin):
    def process_request(self, request):
        assert hasattr(request,
                       'user'), "The Login Required middleware requires authentication middleware to be installed."

        issuer = request.GET.get('iss', None)
        if issuer:
            url = get_oauth2_authentication_uri_from_name(request)
            if url:
                return HttpResponseRedirect(url)
        return None
