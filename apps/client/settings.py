# Django settings for client project.
import os

import sys

from django.urls import reverse_lazy

try:
    RUNNING_DEVSERVER = (sys.argv[1] == 'runserver')
except:
    RUNNING_DEVSERVER = False

RUNNING_TEST = 'test' in sys.argv

if RUNNING_DEVSERVER:
    INTERNAL_IPS = ('127.0.0.1',)
    DEBUG = True
else:
    DEBUG = False

if DEBUG:
    EMAIL_BACKEND = 'django.core.mail.backends.console.EmailBackend'

DEBUG_REQUESTS = False
# ALLOWED_HOSTS = ['oauth-python-sample.g10f.de', 'localhost']
ALLOWED_HOSTS = ['*']
SILENCED_SYSTEM_CHECKS = ['admin.E408']
DEFAULT_AUTO_FIELD = 'django.db.models.AutoField'
DEBUG = os.environ.get('DEBUG', DEBUG)
INTERNAL_IPS = ('127.0.0.1',)
BASE_DIR = os.path.dirname(os.path.dirname(__file__))

ADMINS = (
    ('Gunnar Scherf', 'gunnar@g10f.de'),
)
BRAND = 'G10F+'
ABOUT = 'http://g10f.de/'
OPENID_SSO_SERVER_BASE_URL = 'https://sso.g10f.de/'
SITE_ID = 1
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql_psycopg2',
        'NAME': 'client',
        'USER': 'client',
        'PASSWORD': 'client',
        'HOST': 'localhost',
        'PORT': '5432',
    }}

TIME_ZONE = 'Europe/Berlin'
LANGUAGE_CODE = 'en-us'

# SITE_ID = 1

USE_I18N = True
USE_L10N = True
USE_TZ = True

gettext = lambda s: s

LANGUAGES = (
    ('en', gettext('English')),
    ('de', gettext('Deutsch')),
)

MEDIA_ROOT = os.path.join(BASE_DIR, '../../../static/htdocs/oauth-python-sample.g10f.de/media')
MEDIA_URL = ''
STATIC_ROOT = os.path.join(BASE_DIR, '../../../static/htdocs/oauth-python-sample.g10f.de/static')
STATIC_URL = '/static/'

LOGIN_URL = reverse_lazy('login')
LOGIN_REDIRECT_URL = reverse_lazy('login')
SESSION_COOKIE_NAME = 'client_session_id'

SSO = {
    'STAFF_GROUPS': ['Staff', 'Superuser'],
    'APP_UUID': os.environ.get('SSO.APP_UUID', 'ec1e39cbe3e746c787b770ace4165d13'),
    'APP_NAME': 'OAuth2 Test',
    'OPENID_CHECK_ROLES': False
}

AUTHENTICATION_BACKENDS = (
    'client.oauth2.backend.OAuth2Backend',
    'django.contrib.auth.backends.ModelBackend'
)

AUTH_USER_MODEL = 'oauth2.User'
SESSION_ENGINE = 'django.contrib.sessions.backends.signed_cookies'
# SESSION_COOKIE_AGE = 60 * 10  # seconds * Minutes
SESSION_EXPIRE_AT_BROWSER_CLOSE = True
SESSION_COOKIE_SAMESITE = 'None'

# Additional locations of static files
STATICFILES_DIRS = (
    os.path.join(BASE_DIR, 'client/static'),
)

# List of finder classes that know how to find static files in
# various locations.
STATICFILES_FINDERS = [
    'django.contrib.staticfiles.finders.FileSystemFinder',
    'django.contrib.staticfiles.finders.AppDirectoriesFinder',
    # 'django.contrib.staticfiles.finders.DefaultStorageFinder',
]

# Make this unique, and don't share it with anybody.
SECRET_KEY = os.environ.get('SECRET_KEY', '&amp;9w&amp;vwpc7uahoddb0e+^oyh#v@=hjemup0zb0t^8a++!r1lypp')

if DEBUG:
    # don't use cached loader
    LOADERS = [
        'django.template.loaders.filesystem.Loader',
        'django.template.loaders.app_directories.Loader',
    ]
else:
    LOADERS = [
        ('django.template.loaders.cached.Loader', (
            'django.template.loaders.filesystem.Loader',
            'django.template.loaders.app_directories.Loader',
        )),
    ]

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [
            os.path.join(BASE_DIR, 'client/templates'),
        ],
        # 'APP_DIRS': True,  # must not be set if loaders is set
        'OPTIONS': {
            'context_processors': [
                'django.contrib.auth.context_processors.auth',
                'django.template.context_processors.debug',
                'django.template.context_processors.i18n',
                'django.template.context_processors.media',
                'django.template.context_processors.static',
                "django.template.context_processors.request",
                'django.contrib.messages.context_processors.messages',
                'client.context_processors.settings',
            ],
            'loaders': LOADERS,
            'debug': DEBUG
        },
    },
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    # 'django.contrib.auth.middleware.AuthenticationMiddleware',
    'client.oauth2.middleware.OAuthAuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'django.middleware.locale.LocaleMiddleware',
    'client.oauth2.middleware.LoginMiddleware',
]

ROOT_URLCONF = 'client.urls'
WSGI_APPLICATION = 'client.wsgi.application'

INSTALLED_APPS = (
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.sites',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'django.contrib.flatpages',
    'django.contrib.admin',
    'django.contrib.admindocs',
    'sorl.thumbnail',
    'client.oauth2',
    'client',
)

DEFAULT_FROM_EMAIL = 'webmaster@g10f.de'
SERVER_EMAIL = 'webmaster@g10f.de'

LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '%(levelname)s %(asctime)s %(module)s %(lineno)d %(process)d %(thread)d %(message)s'
        },
        'simple': {
            'format': '%(levelname)s %(message)s'
        },
    },
    'filters': {
        'require_debug_false': {
            '()': 'django.utils.log.RequireDebugFalse',
        },
    },
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
            'formatter': 'simple',
        },
        'mail_admins': {
            'level': 'ERROR',
            'filters': ['require_debug_false'],
            'class': 'django.utils.log.AdminEmailHandler',
            'formatter': 'verbose',
        }
    },
    'root': {
        'handlers': ['console', 'mail_admins'],
        'level': os.getenv('ROOT_LOG_LEVEL', 'INFO'),
    },
    'loggers': {
        'client.oauth2': {
            'handlers': ['console'],
            'level': os.getenv('DJANGO_LOG_LEVEL', 'INFO'),
            'propagate': False,
        },
        'django': {
            'handlers': ['console', 'mail_admins'],
            'level': os.getenv('DJANGO_LOG_LEVEL', 'INFO'),
            'propagate': False,
        },
    },
}
