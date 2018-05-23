import json
from datetime import timedelta
from urllib.parse import urlsplit, urlunsplit, urlparse, urlunparse

from django.conf import settings
from django.contrib import messages
from django.contrib.auth import REDIRECT_FIELD_NAME, login as auth_login, logout as auth_logout, authenticate
from django.contrib.auth.decorators import login_required
from django.contrib.auth.views import redirect_to_login
from django.core.exceptions import ObjectDoesNotExist
from django.http import Http404
from django.http import HttpResponseRedirect, QueryDict
from django.shortcuts import render
from django.shortcuts import resolve_url, get_object_or_404
from django.urls import reverse
from django.utils.decorators import method_decorator
from django.utils.encoding import force_text
from django.utils.http import is_safe_url, urlquote_plus
from django.utils.timezone import now
from django.utils.translation import ugettext as _
from django.views.decorators.cache import never_cache
from django.views.generic import TemplateView
from django.views.generic.base import RedirectView

from client.oauth2.backend import get_userinfo, OAuth2Error, replace_or_add_query_param, get_access_token, url_update
from client.oauth2.crypt import _json_encode, _urlsafe_b64encode, _urlsafe_b64decode
from client.oauth2.models import Client, AccessToken, IdToken, Nonce, MAX_AGE, CodeVerifier


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


def get_state(request, max_age=MAX_AGE):
    state = request.GET.get('state')
    if state is None:
        return {}
    try:
        data = json.loads(_urlsafe_b64decode(state).decode('utf-8'))
    except Exception as e:
        raise OAuth2Error("State '%s' can't be load in to JSON. '%s'" % (state, e), 'invalid_state')

    try:
        nonce = Nonce.objects.filter(value=data.get('nonce'), client=data.get('client')).latest()
        # delete the nonce if used once
        nonce.delete()
    except ObjectDoesNotExist:
        raise OAuth2Error("Nonce %s for provider %s not found." % (data.get('nonce'), data.get('provider')),
                          'invalid_state')

    age = now() - nonce.timestamp
    max_age = timedelta(seconds=max_age)
    if age > max_age:
        raise OAuth2Error('Nonce age %s is exceeding max age %s' % (age, max_age), 'nonce_expired')

    return data


def build_state(client, data=None):
    """
    data can be a dict with additional information
    """
    if data is None:
        data = {}
    nonce = Nonce.objects.create(client=client)
    data.update({'nonce': nonce.value, 'client': client.id})
    return _urlsafe_b64encode(_json_encode(data).encode('ascii'))


def get_oauth2_authentication_uri(client, response_type, redirect_uri, data=None, prompt=None, id_token_hint=None):
    if data is None:
        data = {}
    query = {
        'nonce': Nonce.objects.create(client=client).value,
        'client_id': client.client_id,
        'state': build_state(client, data),
        'response_type': response_type,
        'redirect_uri': redirect_uri
    }
    if client.default_scopes:
        query['scope'] = client.default_scopes
    if client.claims:
        query['claims'] = client.claims.encode('ascii')
    if client.max_age:
        query['max_age'] = client.max_age.seconds
    if client.acr_values:
        query['acr_values'] = client.acr_values

    # PKCE
    if client.type == 'native' and not client.client_secret:
        query['code_challenge'] = CodeVerifier.objects.create(client=client).code_challenge

    if prompt is not None:
        query['prompt'] = prompt
    if id_token_hint is not None:
        query['id_token_hint'] = id_token_hint

    return update_url(client.identity_provider.authorization_endpoint, query)


def remove_query_param(url, param):
    url_parts = list(urlparse(url))
    querystring = QueryDict(url_parts[4], mutable=True)
    querystring.pop(param)
    url_parts[4] = querystring.urlencode(safe='/')
    return urlunparse(url_parts)


def get_oauth2_authentication_uri_from_name(request):
    if request.GET.get('iss', None):
        issuer = request.GET['iss']
        user = request.user

        if user.is_authenticated() and (user.identity_provider.issuer == issuer):
            return None
        else:
            client = get_object_or_404(Client, identity_provider__issuer=issuer, is_active=True, type='web')
            # client = get_object_or_404(Client.objects.get_object_or_404(identity_provider__issuer=issuer, is_active=True, type='web')
            next_url = request.get_full_path()
            redirect_uri = request.build_absolute_uri(force_text(settings.LOGIN_URL))
            return get_oauth2_authentication_uri(client, response_type='code', redirect_uri=redirect_uri,
                                                 data={'next': next_url})

    return None


class SessionView(TemplateView):
    def dispatch(self, request, *args, **kwargs):
        return super(SessionView, self).dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        context = super(SessionView, self).get_context_data(**kwargs)
        user = self.request.user
        context['error'] = self.request.GET.get('error', '')
        try:
            if user.is_authenticated():
                client = Client.objects.get(identity_provider=user.identity_provider, type='web')
                redirect_uri = self.request.build_absolute_uri(force_text(settings.LOGIN_URL))
                next_url = reverse('session')
                id_token = IdToken.objects.filter(user=user, client=client).latest()
                context['refresh_token_url'] = get_oauth2_authentication_uri(client, response_type='code',
                                                                             redirect_uri=redirect_uri,
                                                                             data={'next': next_url}, prompt='none',
                                                                             id_token_hint=id_token.raw)
                context['session_state'] = id_token.session_state
                context['client_id'] = client.client_id
                context['origin'] = user.identity_provider.issuer
        except ObjectDoesNotExist:
            pass
        return context


class UserInfoView(TemplateView):
    template_name = 'userinfo.html'

    def get_context_data(self, **kwargs):
        context = super(UserInfoView, self).get_context_data(**kwargs)
        try:
            user = self.request.user
            access_token = get_access_token(user)

            userinfo = get_userinfo(access_token=access_token, uuid=kwargs.get('uuid'))
            userinfo_endpoint = replace_or_add_query_param(access_token.client.identity_provider.userinfo_endpoint,
                                                           'access_token', access_token.token)

            # update_user(access_token.client, userinfo, 'userinfo')
            context['userinfo'] = userinfo
            context['userinfo_endpoint'] = userinfo_endpoint
            context['calenderlist'] = replace_or_add_query_param(
                "https://www.googleapis.com/calendar/v3/users/me/calendarList", 'access_token', access_token.token)

        except Exception as e:
            context['error'] = str(e)

        return context

    @method_decorator(login_required)
    def dispatch(self, *args, **kwargs):
        try:
            return super(UserInfoView, self).dispatch(*args, **kwargs)
        except AccessToken.DoesNotExist:
            # Log in again
            return redirect_to_login(self.request.build_absolute_uri())


class InstalledLoginView(TemplateView):
    template_name = "installed_login.html"

    def get_context_data(self, **kwargs):
        context = super(InstalledLoginView, self).get_context_data(**kwargs)

        authentications = []
        for client in Client.objects.filter(identity_provider__is_active=True, type='native', is_active=True):
            uri = get_oauth2_authentication_uri(client, response_type='code', redirect_uri='urn:ietf:wg:oauth:2.0:oob')
            authentications.append({'name': client.identity_provider.name, 'uri': uri})

        context['authentications'] = authentications
        return context


class UserInfoClientView(TemplateView):
    """
    Example for Implicit Client Profile http://openid.net/specs/openid-connect-implicit-1_0.html
    """
    template_name = "userinfo_client.html"

    def get_context_data(self, **kwargs):
        context = super(UserInfoClientView, self).get_context_data(**kwargs)

        authentications = []
        redirect_uri = self.request.build_absolute_uri()

        for client in Client.objects.filter(identity_provider__is_active=True, is_active=True, type='javascript'):
            data = {
                'userinfo_endpoint': client.identity_provider.userinfo_endpoint,
                'picture_endpoint': client.identity_provider.picture_endpoint
            }
            uri = get_oauth2_authentication_uri(client, response_type='id_token token', redirect_uri=redirect_uri,
                                                data=data)
            authentications.append({'name': client.identity_provider.name, 'uri': uri, 'client_id': client.client_id})

        context['authentications'] = authentications
        return context


@never_cache
def login(request, redirect_field_name=REDIRECT_FIELD_NAME):
    # The original url from the client the user  requested
    next_url = request.POST.get(redirect_field_name, request.GET.get(redirect_field_name, ''))
    # Ensure the user-originating redirection url is safe.
    if not is_safe_url(url=next_url, host=request.get_host()):
        next_url = resolve_url(settings.LOGIN_REDIRECT_URL)

    code = request.GET.get('code')  # OAuth 2
    error = request.GET.get('error')  # OAuth 2
    redirect_uri = request.build_absolute_uri(force_text(settings.LOGIN_URL))

    authentications = []
    for client in Client.objects.filter(identity_provider__is_active=True, is_active=True, type='web'):
        uri = get_oauth2_authentication_uri(client, response_type='code', redirect_uri=redirect_uri,
                                            data={'next': next_url})
        authentications.append({'name': client.identity_provider.name, 'uri': uri, 'id': client.identity_provider.id})
    state = {}
    try:
        state = get_state(request)
        if error:
            raise OAuth2Error(error, 'error', state=state)

        if code:
            # oauth2 session management
            session_state = request.GET.get('session_state', '')
            next_url = state['next']

            client = Client.objects.get(id=state['client'])
            user = authenticate(client=client, code=code, redirect_uri=redirect_uri, session_state=session_state)

            auth_login(request, user)

            if request.session.test_cookie_worked():
                request.session.delete_test_cookie()
            # oauth2 session management
            if next_url == reverse('session'):
                return HttpResponseRedirect(next_url)

            messages.success(request, _('Welcome, %(user)s, you are logged in with <strong>%(provider)s</strong>.') %
                             {'user': user, 'provider': client.identity_provider})
            return render(request, 'login.html', context={'next': next_url, 'authentications': authentications})

            # In production you should redirect to another page, so that the url with the code and state gets not requested again.
            # Here for demonstration, the request from the OAuth2 provider is shown.
            # return HttpResponseRedirect(next_url)
        else:
            return render(request, 'login.html', context={'authentications': authentications})
            # In production you can redirect to the authentication uri from the OAuth2 provider.
            # Here for demonstration, the authentication uri to the OAuth2 provider is shown.
            # return HttpResponseRedirect(identity_provider_authentication_uri)

    except OAuth2Error as e:
        if e.error == 'login_required' and request.user.is_authenticated():
            # oauth2 session management
            auth_logout(request)
            next_url = state.get('next')
            if next_url:
                next_url = url_update(next_url, {'error': e.error, 'description': e.message})
                return HttpResponseRedirect(next_url)
        if e.error == 'application_access_denied':
            auth_logout(request)
            redirect_to = e.state
            if redirect_to:
                next_url = state.get('next', '')
                if next_url:
                    next_url = request.build_absolute_uri(next_url)
                    next_url = url_update(next_url, {'error': e.error, 'description': e.message})
                redirect_to = url_update(redirect_to, {'redirect_uri': next_url})
                return HttpResponseRedirect(redirect_to)

        return render(request, 'oauth2/error.html', context={'error': e})


@never_cache
def logout(request, redirect_field_name=REDIRECT_FIELD_NAME):
    """
    Logs out the user and displays 'You are logged out' message.
    """
    redirect_to = resolve_url(settings.LOGIN_REDIRECT_URL)
    next_url = request.POST.get(redirect_field_name, request.GET.get(redirect_field_name, ''))
    # Ensure the user-o riginating redirection url is safe.
    if not is_safe_url(url=next_url, host=request.get_host()):
        next_url = resolve_url(settings.LOGIN_REDIRECT_URL)

    if request.user.is_authenticated():
        identity_provider = request.user.identity_provider
        auth_logout(request)
        if identity_provider:
            next_url = urlquote_plus(request.build_absolute_uri(next_url))
            # TODO replace next with post_logout_redirect_uri 
            # see http://openid.net/specs/openid-connect-session-1_0.html#RPLogout
            redirect_to = "%s?next=%s" % (identity_provider.end_session_endpoint, next_url)

    return HttpResponseRedirect(redirect_to)


class IdentityProviderRedirectView(RedirectView):
    uri_name = None

    @method_decorator(login_required)
    def dispatch(self, request, *args, **kwargs):
        return super(IdentityProviderRedirectView, self).dispatch(request, *args, **kwargs)

    def get_redirect_url(self):
        if not self.uri_name:
            raise Http404('uri_name was not defined.')
        identity_provider = self.request.user.identity_provider
        uri = getattr(identity_provider, self.uri_name, None)
        if not uri:
            raise Http404('value of %s for provider %s is not configured.' % (self.uri_name, identity_provider))
        return uri
