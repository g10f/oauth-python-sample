import base64
import hashlib
import json
from datetime import datetime
from functools import partial

import requests
from django.conf import settings
from django.contrib.auth.models import UserManager, Group, AbstractBaseUser, PermissionsMixin
from django.core.cache import cache
from django.core.exceptions import ObjectDoesNotExist
from django.core.mail import send_mail
from django.db import models
from django.utils import timezone
from django.utils.crypto import get_random_string
from django.utils.functional import lazystr
from django.utils.http import urlquote
from django.utils.text import Truncator
from django.utils.translation import ugettext_lazy as _

from .utils import OAuth2Error

MAX_AGE = 600


def update_object_from_dict(destination, source_dict, key_mapping=None):
    """
    check if the values in the destination object differ from
    the values in the source_dict and update if needed
    """
    if key_mapping is None:
        key_mapping = {}
    field_names = [f.name for f in destination._meta.fields]
    new_object = True if destination.pk is None else False
    updated = False

    for key in source_dict:
        field_name = key_mapping.get(key, key)
        if field_name in field_names:
            new_value = source_dict[key]
            if new_object:
                setattr(destination, field_name, new_value)
            else:
                old_value = getattr(destination, field_name)
                if old_value != new_value:
                    setattr(destination, field_name, new_value)
                    updated = True
    if updated or new_object:
        destination.save()


class IdentityProvider(models.Model):
    issuer = models.CharField(_("issuer"), max_length=255, blank=True)
    name = models.CharField(_("name"), max_length=255, unique=True)
    uri = models.URLField(_('Home url'), blank=True, default='', max_length=2048)
    authorization_endpoint = models.URLField(_('authentication uri'), max_length=2048)
    token_endpoint = models.URLField(_('token uri'), max_length=2048)
    end_session_endpoint = models.URLField(_('logout uri'), blank=True, max_length=2048)
    revoke_uri = models.URLField(_('revoke uri'), blank=True, max_length=2048)
    userinfo_endpoint = models.URLField(_('userinfo uri'), blank=True, max_length=2048)
    picture_endpoint = models.URLField(_('picture uri'), blank=True, max_length=2048, default='')
    jwks_uri = models.URLField(_('JSON Web Keys uri'), blank=True, max_length=2048)
    profile_uri = models.URLField(_('uri for HTML View to change the profile'), blank=True, default='',
                                  max_length=2048)  # ok
    is_supporting_http_auth_header = models.BooleanField(_('is supporting http auth header'), default=True)
    check_session_iframe = models.URLField(_('check_session_iframe uri'), blank=True, default='', max_length=2048)
    user_navigation_uri = models.URLField(_('user navigation uri'), blank=True, default='', max_length=2048)
    is_active = models.BooleanField(_('is active'), default=True)
    order = models.IntegerField(default=0, help_text=_('Overwrites the alphabetic order.'))
    is_secure = models.BooleanField(_('is secure'), default=True)
    check_roles = models.BooleanField(_('check roles'), default=False)
    extend_access_uri = models.URLField(_('extend access uri'), blank=True, default='', max_length=2048)

    class Meta:
        ordering = ['order', 'name']
        verbose_name = _('Identity Provider')
        verbose_name_plural = _('Identity Providers')

    @property
    def jwks(self):
        if not self.jwks_uri:
            return None
        cache_key = '%s.pub_keys' % self.jwks_uri
        pub_keys = cache.get(cache_key)
        if pub_keys is None:
            r = requests.get(self.jwks_uri, verify=self.is_secure)
            pks = r.json()
            pub_keys = []
            for key in pks['keys']:
                pub_keys.append(key)
            timeout = r.headers.get('max-age', 60)
            cache.add(cache_key, pub_keys, timeout=timeout)
            return cache.get(cache_key)
        return pub_keys

    def __str__(self):
        return self.name


CLIENT_TYPES = [
    ('web', _('Web Application')),  # response_type=code  grant_type=authorization_code or refresh_token
    ('javascript', _('Javascript Application')),  # response_type=token
    ('native', _('Native Application')),  # response_type=code  grant_type=authorization_code or refresh_token
    # redirect_uris=http://localhost or  urn:ietf:wg:oauth:2.0:oob
    ('service', _('Service Account')),  # grant_type=client_credentials
    ('trusted', _('Trusted Client'))  # grant_type=password
]


class Client(models.Model):
    name = models.CharField(_("name"), max_length=255, blank=True)
    response_type = models.CharField(_("response type"), blank=True, max_length=255)
    identity_provider = models.ForeignKey(IdentityProvider, on_delete=models.CASCADE)
    type = models.CharField(_('type'), max_length=255, choices=CLIENT_TYPES, default='web')
    default_scopes = models.CharField(_("default scopes"), blank=True, max_length=2048)
    application_id = models.CharField(_("application id"), blank=True, max_length=255)
    client_id = models.CharField(_("client id"), max_length=255)
    client_secret = models.CharField(_("client secret"), blank=True, max_length=255)
    is_active = models.BooleanField(_('is active'), default=True)
    claims = models.TextField(_("claims"), blank=True)
    max_age = models.DurationField(_("max_age"), blank=True, null=True)
    acr_values = models.CharField(_("acr_values"), blank=True, max_length=255)
    use_pkce = models.BooleanField(_('use PKCE'), default=False)
    redirect_uri = models.CharField(_("redirect uri"), default=lazystr(settings.LOGIN_URL), blank=True,
                                    max_length=2048)
    ui_locales = models.CharField(
        _("ui locales"), blank=True, max_length=255,
        help_text=_('See http://openid.net/specs/openid-connect-core-1_0.html#AuthRequest'))
    claims_locales = models.CharField(
        _("claims locales"), blank=True, max_length=255,
        help_text=_('See http://openid.net/specs/openid-connect-core-1_0.html#ClaimsLanguagesAndScripts'))
    prompt = models.CharField(
        _("prompt"), blank=True, max_length=255,
        help_text=_('See http://openid.net/specs/openid-connect-core-1_0.html#AuthRequest'))

    # client.type == 'native' and not client.client_secret:
    # redirect_uri = models.URLField(_('redirect uri for native app'), blank=True, max_length=2048)

    class Meta:
        ordering = ['identity_provider', 'name']
        # unique_together = (("identity_provider", "type"),)

    def __str__(self):
        return "%s - %s" % (self.name, self.identity_provider)

    def get_redirect_uri(self, request):
        return request.build_absolute_uri(self.redirect_uri)

    @property
    def tooltip(self):
        t = {}

        def add(*args):
            for arg in args:
                if getattr(self, arg):
                    t[arg] = str(getattr(self, arg))

        add('default_scopes', 'claims', 'max_age', 'acr_values', 'ui_locales', 'claims_locales', 'prompt', 'use_pkce')

        return "{t}".format(t=t)


class ApiClient(models.Model):
    identity_provider = models.ForeignKey(IdentityProvider, on_delete=models.CASCADE)
    client_id = models.CharField(_("client id"), max_length=255)
    is_active = models.BooleanField(_('is active'), default=True)

    class Meta:
        unique_together = (("identity_provider", "client_id"),)

    def __str__(self):
        return "%s - %s" % (self.identity_provider, self.client_id)


class Nonce(models.Model):
    value = models.CharField(_("value"), db_index=True, max_length=12, default=get_random_string)
    client = models.ForeignKey(Client, on_delete=models.CASCADE)
    timestamp = models.DateTimeField(auto_now_add=True)

    class Meta:
        get_latest_by = "timestamp"

    def __str__(self):
        return self.value


class CodeVerifier(models.Model):
    value = models.CharField(_("value"), db_index=True, max_length=128, default=partial(get_random_string, length=128))
    client = models.ForeignKey(Client, on_delete=models.CASCADE)
    timestamp = models.DateTimeField(auto_now_add=True)

    class Meta:
        get_latest_by = "timestamp"

    def __str__(self):
        return "%s" % self.value

    @property
    def code_challenge(self):
        digest = hashlib.sha256(self.value.encode('ascii')).digest()
        return base64.urlsafe_b64encode(digest).rstrip(b'=')

    @property
    def code_challenge_method(self):
        return 'S256'


class Organisation(models.Model):
    name = models.CharField(_("name"), max_length=255)
    uuid = models.CharField(_("uuid"), unique=True, max_length=36)  # UUIDField(version=4, unique=True, editable=True)

    def __str__(self):
        return self.name


class User(AbstractBaseUser, PermissionsMixin):
    unique_name = models.CharField(_('unique name'), unique=True, max_length=255)
    uuid = models.CharField(_("uuid"), max_length=36)  # hex value of uuid
    identity_provider = models.ForeignKey(IdentityProvider, blank=True, null=True, on_delete=models.CASCADE)
    organisations = models.ManyToManyField(Organisation, blank=True)
    # original Django fields, except that username is not unique
    username = models.CharField(_('username'), max_length=255)
    first_name = models.CharField(_('first name'), max_length=255, blank=True)
    last_name = models.CharField(_('last name'), max_length=255, blank=True)
    email = models.EmailField(_('email address'), blank=True)
    is_staff = models.BooleanField(_('staff status'), default=False,
                                   help_text=_('Designates whether the user can log into this admin site.'))
    is_active = models.BooleanField(_('active'), default=True, help_text=_(
        'Designates whether this user should be treated as active. Unselect this instead of deleting accounts.'))
    date_joined = models.DateTimeField(_('date joined'), default=timezone.now)

    objects = UserManager()

    USERNAME_FIELD = 'unique_name'
    REQUIRED_FIELDS = ['email', 'uuid']

    class Meta:
        unique_together = (("uuid", "identity_provider"),)
        verbose_name = _('user')
        verbose_name_plural = _('users')

    def get_absolute_url(self):
        return "/users/%s/" % urlquote(self.username)

    def get_full_name(self):
        """
        Returns the first_name plus the last_name, with a space in between.
        """
        full_name = '%s %s' % (self.first_name, self.last_name)
        full_name = full_name.strip()
        if not full_name:
            full_name = self.username
        return full_name

    def get_short_name(self):
        """Returns the short name for the user."""
        return self.first_name

    def email_user(self, subject, message, from_email=None):
        """
        Sends an email to this User.
        """
        send_mail(subject, message, from_email, [self.email])

    @property
    def application_id(self):
        try:
            return AccessToken.objects.filter(user=self, client__identity_provider=self.identity_provider).latest().\
                client.application_id
        except ObjectDoesNotExist:
            return ""

    def get_user_apps_url(self):
        return self.identity_provider.user_navigation_uri

    def get_identity_provider(self):
        return self.identity_provider

    def __str__(self):
        return self.username


class AccessToken(models.Model):
    client = models.ForeignKey(Client, on_delete=models.CASCADE)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    token = models.CharField(_("token"), max_length=16384)
    type = models.CharField(_("type"), max_length=255)
    expires_at = models.DateTimeField(_('expires at'))
    scope = models.CharField(_("scope"), max_length=2048, blank=True)

    class Meta:
        get_latest_by = "expires_at"

    def __str__(self):
        return Truncator(self.token).chars(30)


class RefreshToken(models.Model):
    access_token = models.OneToOneField(AccessToken, related_name='refresh_token', on_delete=models.CASCADE)
    token = models.CharField(_("token"), max_length=2048)

    def __str__(self):
        return self.token


class IdToken(models.Model):
    client = models.ForeignKey(Client, on_delete=models.CASCADE)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    aud = models.CharField(_("audience"), max_length=255)
    email = models.CharField(_("email"), max_length=255, blank=True)
    exp = models.DateTimeField(_("expires at"))
    iat = models.DateTimeField(_("issued at"))
    iss = models.CharField(_('issuer'), max_length=255)
    sub = models.CharField(_("subject"), max_length=255)
    roles = models.CharField(_("roles"), blank=True, max_length=2048)  # custom field 
    content = models.TextField(_("JSON content"))
    auth_time = models.DateTimeField(_("authentication time"), blank=True, null=True)
    raw = models.TextField(_("raw content"), blank=True, default="")
    session_state = models.TextField(_("session state"), blank=True, default="")
    acr = models.TextField(_("Authentication Context Class Reference"), blank=True, default="")

    class Meta:
        get_latest_by = "exp"
        verbose_name = _('ID Token')
        verbose_name_plural = _('ID Tokens')

    @classmethod
    def create_from_token(cls, id_token_content, client):
        if id_token_content.get('auth_time', None):
            auth_time = timezone.make_aware(datetime.utcfromtimestamp(id_token_content['auth_time']), timezone.utc)
        else:
            auth_time = None
        raw = id_token_content['raw']
        del id_token_content['raw']
        obj = cls(client=client,
                  raw=raw,
                  aud=id_token_content['aud'],
                  exp=timezone.make_aware(datetime.utcfromtimestamp(id_token_content['exp']), timezone.utc),
                  iat=timezone.make_aware(datetime.utcfromtimestamp(id_token_content['iat']), timezone.utc),
                  iss=id_token_content['iss'],
                  sub=id_token_content['sub'],
                  email=id_token_content.get('email', ''),
                  auth_time=auth_time,
                  roles=id_token_content.get('roles', ''),  # custom optional field            
                  content=json.dumps(id_token_content))

        return obj

    def __str__(self):
        return Truncator(self.content).chars(20)


class Role(models.Model):
    group = models.OneToOneField(Group, on_delete=models.CASCADE)

    def __str__(self):
        return self.group.name


def update_roles(user, roles):
    for app_role in roles:
        group = Group.objects.get_or_create(name=app_role)[0]
        Role.objects.get_or_create(group=group)

    current_app_roles = set(user.groups.filter(role__id__isnull=False))
    desired_app_roles = set(Group.objects.filter(name__in=roles))

    is_updated = False
    remove_groups = current_app_roles - desired_app_roles
    if remove_groups:
        is_updated = True
        user.groups.remove(*remove_groups)

    add_groups = desired_app_roles - current_app_roles
    if add_groups:
        is_updated = True
        user.groups.add(*add_groups)

    is_staff = False
    is_superuser = False
    # is_active = True if roles else False
    is_active = True

    staff_groups = settings.SSO.get('STAFF_GROUPS', [])
    for group in user.groups.all():
        if group.name in staff_groups:
            is_staff = True
        if group.name == 'Superuser':
            is_superuser = True
            is_staff = True
            break

    if user.is_staff != is_staff:
        is_updated = True
        user.is_staff = is_staff
    if user.is_superuser != is_superuser:
        is_updated = True
        user.is_superuser = is_superuser
    if user.is_active != is_active:
        is_updated = True
        user.is_active = is_active

    if is_updated:
        user.save()


def map_data(defaults, data):
    for (key, value) in data.items():
        name_mapping = _name_mapping.get(key)
        if name_mapping:
            if hasattr(name_mapping, '__call__'):
                name_mapping(defaults, value)
            else:
                defaults[name_mapping] = value


_name_mapping = {
    'id': 'uuid',
    'sub': 'uuid',
    'name': 'username',
    'given_name': 'first_name',
    'family_name': 'last_name',
    'email': 'email',
    'access_token': map_data,
    'vw_id': 'uuid'
}


def _has_access(data):
    try:
        if len(data['roles']) > 0:
            return True
    except KeyError:
        return False
    return False


def update_user(client, data):
    identity_provider = client.identity_provider
    defaults = {'email': '', 'is_active': True}  # default blank email for not null db constraint
    map_data(defaults, data)

    defaults['unique_name'] = "%s.%s" % (identity_provider, defaults['uuid'])
    if not 'username' in defaults:
        defaults['username'] = defaults['unique_name']
    # create or update user
    user = User.objects.get_or_create(uuid=defaults['uuid'], identity_provider=identity_provider, defaults=defaults)[0]
    update_object_from_dict(user, defaults)

    # create or update Roles
    if 'roles' in data:
        update_roles(user, data['roles'])

    # create or update organisations
    if 'organisations' in data:
        organisations = []
        for uuid, organisation_data in data['organisations'].items():
            organisation = Organisation.objects.get_or_create(uuid=uuid)[0]
            update_object_from_dict(organisation, organisation_data)
            organisations.append(organisation)

        user.organisations.set(organisations)

    if client.identity_provider.check_roles:
        if not _has_access(data):
            try:
                user = User.objects.get(uuid=defaults['uuid'], identity_provider=identity_provider)
                user.is_active = False
                user.save()
            except User.DoesNotExist:
                pass
            raise OAuth2Error(_("Sorry, you don't have access to this application"), 'application_access_denied',
                              state=client.identity_provider.extend_access_uri)

    return user
