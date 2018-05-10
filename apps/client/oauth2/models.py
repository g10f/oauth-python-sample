import json

import requests
from datetime import datetime
from django.conf import settings
from django.contrib.auth.models import UserManager, Group, AbstractBaseUser, PermissionsMixin
from django.core.cache import cache
from django.core.exceptions import ObjectDoesNotExist
from django.core.mail import send_mail
from django.db import models
from django.utils import timezone
from django.utils.crypto import get_random_string
from django.utils.http import urlquote
from django.utils.text import Truncator
from django.utils.translation import ugettext_lazy as _
from six import python_2_unicode_compatible

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


@python_2_unicode_compatible
class IdentityProvider(models.Model):
    issuer = models.CharField(_("issuer"), max_length=255, blank=True)  # ok
    name = models.CharField(_("name"), max_length=255)
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
            r = requests.get(self.jwks_uri)
            pks = r.json()
            pub_keys = []
            for key in pks['keys']:
                pub_keys.append(key)
            timeout = r.headers.get('max-age', 60)
            cache.add(cache_key, pub_keys, timeout=timeout)
            return cache.get(cache_key)
        return pub_keys

    def __str__(self):
        return "%s" % self.name


CLIENT_TYPES = [
    ('web', _('Web Application')),  # response_type=code  grant_type=authorization_code or refresh_token
    ('javascript', _('Javascript Application')),  # response_type=token
    ('native', _('Native Application')),
    # response_type=code  grant_type=authorization_code or refresh_token redirect_uris=http://localhost or  urn:ietf:wg:oauth:2.0:oob
    ('service', _('Service Account')),  # grant_type=client_credentials
    ('trusted', _('Trusted Client'))  # grant_type=password
]


@python_2_unicode_compatible
class Client(models.Model):
    identity_provider = models.ForeignKey(IdentityProvider)
    type = models.CharField(_('type'), max_length=255, choices=CLIENT_TYPES, default='web')
    default_scopes = models.CharField(_("default scopes"), blank=True, max_length=2048)
    application_id = models.CharField(_("application id"), blank=True, max_length=255)
    client_id = models.CharField(_("client id"), max_length=255)
    client_secret = models.CharField(_("client secret"), blank=True, max_length=255)
    is_active = models.BooleanField(_('is active'), default=True)

    # redirect_uri = models.URLField(_('redirect uri for native app'), blank=True, max_length=2048)

    class Meta:
        ordering = ['identity_provider', 'type']
        unique_together = (("identity_provider", "type"),)

    def __str__(self):
        return "%s - %s" % (self.identity_provider, self.get_type_display())


@python_2_unicode_compatible
class ApiClient(models.Model):
    identity_provider = models.ForeignKey(IdentityProvider)
    client_id = models.CharField(_("client id"), max_length=255)
    is_active = models.BooleanField(_('is active'), default=True)

    class Meta:
        unique_together = (("identity_provider", "client_id"),)

    def __str__(self):
        return "%s - %s" % (self.identity_provider, self.client_id)


@python_2_unicode_compatible
class Nonce(models.Model):
    value = models.CharField(_("value"), db_index=True, max_length=12, default=get_random_string)
    client = models.ForeignKey(Client)
    timestamp = models.DateTimeField(auto_now_add=True)

    class Meta:
        get_latest_by = "timestamp"

    def __str__(self):
        return "%s" % self.value


@python_2_unicode_compatible
class Organisation(models.Model):
    name = models.CharField(_("name"), max_length=255)
    uuid = models.CharField(_("uuid"), unique=True, max_length=36)  # UUIDField(version=4, unique=True, editable=True)

    def __str__(self):
        return "%s" % self.name


@python_2_unicode_compatible
class User(AbstractBaseUser, PermissionsMixin):
    unique_name = models.CharField(_('unique name'), unique=True, max_length=255)
    uuid = models.CharField(_("uuid"), max_length=36)  # hex value of uuid
    identity_provider = models.ForeignKey(IdentityProvider, blank=True, null=True)
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
        "Returns the short name for the user."
        return self.first_name

    def email_user(self, subject, message, from_email=None):
        """
        Sends an email to this User.
        """
        send_mail(subject, message, from_email, [self.email])

    @property
    def application_id(self):
        try:
            return AccessToken.objects.filter(user=self,
                                              client__identity_provider=self.identity_provider).latest().client.application_id
        except ObjectDoesNotExist:
            return ""

    def get_user_apps_url(self):
        return self.identity_provider.user_navigation_uri

    def get_identity_provider(self):
        return self.identity_provider

    def __str__(self):
        return '%s' % self.username


@python_2_unicode_compatible
class AccessToken(models.Model):
    client = models.ForeignKey(Client)
    user = models.ForeignKey(User)
    token = models.CharField(_("token"), max_length=2048)
    type = models.CharField(_("type"), max_length=255)
    expires_at = models.DateTimeField(_('expires at'))
    scope = models.CharField(_("scope"), max_length=2048, blank=True)

    class Meta:
        get_latest_by = "expires_at"

    def __str__(self):
        return Truncator(self.token).chars(30)


@python_2_unicode_compatible
class RefreshToken(models.Model):
    access_token = models.OneToOneField(AccessToken, related_name='refresh_token')
    token = models.CharField(_("token"), max_length=2048)

    def __str__(self):
        return self.token


@python_2_unicode_compatible
class IdToken(models.Model):
    client = models.ForeignKey(Client)
    user = models.ForeignKey(User)
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
        obj = cls(client=client,
                  raw=id_token_content['raw'],
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
        return self.content[:20]


@python_2_unicode_compatible
class Role(models.Model):
    group = models.OneToOneField(Group)

    def __str__(self):
        return "%s" % self.group.name


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
    is_active = True if roles else False

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

        user.organisations = organisations

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
