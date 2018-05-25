from django.conf import settings
from django.conf.urls import include, url
from django.contrib.staticfiles.urls import staticfiles_urlpatterns
from django.urls import path
from django.views.generic import RedirectView
from client.oauth2.views import IdentityProviderRedirectView
from client.views import home, api_test

from . import admin

urlpatterns = [
    url(r'^$', home, name='home'),
    url(r'^api/v1/test/$', api_test, name='api_test'),
    url(r'^about/$', RedirectView.as_view(url=settings.ABOUT, permanent=False), name='about'),
    url(r'^auth_profile/$', IdentityProviderRedirectView.as_view(uri_name='profile_uri', permanent=False), name='auth_profile'),
    url(r'^oauth2/', include('client.oauth2.urls')),
    path('admin/', admin.site.urls),
] + staticfiles_urlpatterns()
