import logging

from django.conf import settings as site_settings

from client import __version__

log = logging.getLogger(__name__)


def settings(request):
    return {'brand': site_settings.BRAND,
            'sso_base_url': site_settings.OPENID_SSO_SERVER_BASE_URL,
            'app_name': site_settings.SSO['APP_NAME'],
            'version': __version__
            }
