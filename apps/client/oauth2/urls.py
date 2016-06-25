from django.conf.urls import url

from .views import UserInfoClientView, UserInfoView, InstalledLoginView, login, logout, SessionView

urlpatterns = [
    url(r'^login/$', login, name='login'),
    url(r'^logout/$', logout, name='logout'),
    url(r'^userinfo/me/$', UserInfoView.as_view(), name='userinfo_me'),
    url(r'^userinfo/client/$', UserInfoClientView.as_view(), name='userinfo_client'),
    url(r'^login/installed/$', InstalledLoginView.as_view(), name='login_installed'),
    url(r'^userinfo/(?P<uuid>[a-z0-9]{32})/$', UserInfoView.as_view(), name='userinfo'),
    url(r'^session/$', SessionView.as_view(template_name="oauth2/session.html"), name='session'),
]
