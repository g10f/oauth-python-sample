from django.urls import path

from .views import UserInfoClientView, UserInfoView, login, logout, SessionView

urlpatterns = [
    path('login/', login, name='login'),
    path('logout/', logout, name='logout'),
    path('userinfo/me/', UserInfoView.as_view(), name='userinfo_me'),
    path('userinfo/client/', UserInfoClientView.as_view(), name='userinfo_client'),
    # path('login/installed/', InstalledLoginView.as_view(), name='login_installed'),
    path('userinfo/<slug:uuid>/', UserInfoView.as_view(), name='userinfo'),
    path('session/', SessionView.as_view(template_name="oauth2/session.html"), name='session'),
]
