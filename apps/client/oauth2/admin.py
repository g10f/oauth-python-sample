from django import forms
from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as DjangoUserAdmin
from django.contrib.auth.forms import UserChangeForm as DjangoUserChangeForm
from django.contrib.auth.forms import UserCreationForm as DjangoUserCreationForm
from django.utils.translation import gettext_lazy as _

from client.admin import site
from .models import Organisation, Role, User, AccessToken, RefreshToken, IdentityProvider, IdToken, \
    Nonce, Client, ApiClient, CodeVerifier


class UserChangeForm(DjangoUserChangeForm):
    pass
    # class Meta:
    #    model = User


class UserCreationForm(DjangoUserCreationForm):
    def clean_username(self):
        # Since User.username is unique, this check is redundant,
        # but it sets a nicer error message than the ORM. See #13147.
        username = self.cleaned_data["username"]
        try:
            User.objects.get(username=username)
        except User.DoesNotExist:
            return username
        raise forms.ValidationError(self.error_messages['duplicate_username'])

    class Meta:
        model = User
        fields = ("username", 'uuid',)


class UserAdmin(DjangoUserAdmin):
    fieldsets = (
        (None, {'fields': ('username', 'uuid', 'password')}),
        (_('Personal info'), {'fields': ('first_name', 'last_name', 'email', 'organisations')}),
        (_('Permissions'), {'fields': ('is_active', 'is_staff', 'is_superuser', 'groups', 'user_permissions')}),
        (_('Important dates'), {'fields': ('last_login', 'date_joined')}),
    )
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('username', 'uuid', 'password1', 'password2')}
         ),
    )
    filter_horizontal = ('groups', 'user_permissions', 'organisations',)
    list_display = ('username', 'email', 'first_name', 'last_name', 'is_staff', 'identity_provider')
    list_filter = ('is_staff', 'is_superuser', 'is_active', 'groups', 'identity_provider')

    form = UserChangeForm
    add_form = UserCreationForm


class OrganisationAdmin(admin.ModelAdmin):
    list_display = ('name', 'uuid')


class AccessTokenAdmin(admin.ModelAdmin):
    list_display = ('user', 'client', 'type', 'expires_at', '__str__')
    list_filter = ('client',)


class RefreshTokenAdmin(admin.ModelAdmin):
    list_display = ('access_token', 'token')
    list_filter = ('access_token__client',)


class IdTokenAdmin(admin.ModelAdmin):
    list_display = ('id', 'user', 'client', 'aud', 'iss', 'sub', 'exp')
    list_filter = ('client',)


class IdentityProviderAdmin(admin.ModelAdmin):
    list_display = ('name', 'issuer', 'is_active')
    list_filter = ('is_active', 'is_secure', 'client__type', 'is_supporting_http_auth_header')


class NonceAdmin(admin.ModelAdmin):
    list_display = ('value', 'client', 'timestamp')
    list_filter = ('client',)


class CodeVerifierAdmin(admin.ModelAdmin):
    list_display = ('value', 'client', 'timestamp')
    list_filter = ('client',)


class ClientAdmin(admin.ModelAdmin):
    list_display = ('__str__', 'client_id', 'type', 'is_active')
    list_filter = ('type', 'identity_provider',)


class ApiClientAdmin(admin.ModelAdmin):
    list_display = ('identity_provider', 'client_id', 'is_active')
    list_filter = ('identity_provider',)


site.register(User, UserAdmin)
site.register(Organisation, OrganisationAdmin)
site.register(Role)
site.register(AccessToken, AccessTokenAdmin)
site.register(RefreshToken, RefreshTokenAdmin)
site.register(IdToken, IdTokenAdmin)
site.register(IdentityProvider, IdentityProviderAdmin)
site.register(Nonce, NonceAdmin)
site.register(CodeVerifier, CodeVerifierAdmin)
site.register(Client, ClientAdmin)
site.register(ApiClient, ApiClientAdmin)
