# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations
import django.utils.crypto
import django.utils.timezone
from django.conf import settings


class Migration(migrations.Migration):

    dependencies = [
        ('auth', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='User',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('password', models.CharField(max_length=128, verbose_name='password')),
                ('last_login', models.DateTimeField(default=django.utils.timezone.now, verbose_name='last login')),
                ('is_superuser', models.BooleanField(default=False, help_text='Designates that this user has all permissions without explicitly assigning them.', verbose_name='superuser status')),
                ('unique_name', models.CharField(unique=True, max_length=255, verbose_name='unique name')),
                ('uuid', models.CharField(max_length=36, verbose_name='uuid')),
                ('username', models.CharField(max_length=255, verbose_name='username')),
                ('first_name', models.CharField(max_length=255, verbose_name='first name', blank=True)),
                ('last_name', models.CharField(max_length=255, verbose_name='last name', blank=True)),
                ('email', models.EmailField(max_length=75, verbose_name='email address', blank=True)),
                ('is_staff', models.BooleanField(default=False, help_text='Designates whether the user can log into this admin site.', verbose_name='staff status')),
                ('is_active', models.BooleanField(default=True, help_text='Designates whether this user should be treated as active. Unselect this instead of deleting accounts.', verbose_name='active')),
                ('date_joined', models.DateTimeField(default=django.utils.timezone.now, verbose_name='date joined')),
                ('groups', models.ManyToManyField(related_query_name='user', related_name='user_set', to='auth.Group', blank=True, help_text='The groups this user belongs to. A user will get all permissions granted to each of his/her group.', verbose_name='groups')),
            ],
            options={
                'verbose_name': 'user',
                'verbose_name_plural': 'users',
            },
            bases=(models.Model,),
        ),
        migrations.CreateModel(
            name='AccessToken',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('token', models.CharField(max_length=2048, verbose_name='token')),
                ('type', models.CharField(max_length=255, verbose_name='type')),
                ('expires_at', models.DateTimeField(verbose_name='expires at')),
                ('scope', models.CharField(max_length=2048, verbose_name='scope', blank=True)),
            ],
            options={
                'get_latest_by': 'expires_at',
            },
            bases=(models.Model,),
        ),
        migrations.CreateModel(
            name='ApiClient',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('client_id', models.CharField(max_length=255, verbose_name='client id')),
                ('is_active', models.BooleanField(default=True, verbose_name='is active')),
            ],
            options={
            },
            bases=(models.Model,),
        ),
        migrations.CreateModel(
            name='Client',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('type', models.CharField(default=b'web', max_length=255, verbose_name='type', choices=[(b'web', 'Web Application'), (b'javascript', 'Javascript Application'), (b'native', 'Native Application'), (b'service', 'Service Account'), (b'trusted', 'Trusted Client')])),
                ('default_scopes', models.CharField(max_length=2048, verbose_name='default scopes', blank=True)),
                ('application_id', models.CharField(max_length=255, verbose_name='application id', blank=True)),
                ('client_id', models.CharField(max_length=255, verbose_name='client id')),
                ('client_secret', models.CharField(max_length=255, verbose_name='client secret', blank=True)),
                ('is_active', models.BooleanField(default=True, verbose_name='is active')),
            ],
            options={
                'ordering': ['identity_provider', 'type'],
            },
            bases=(models.Model,),
        ),
        migrations.CreateModel(
            name='IdentityProvider',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('issuer', models.CharField(max_length=255, verbose_name='issuer', blank=True)),
                ('name', models.CharField(max_length=255, verbose_name='name')),
                ('uri', models.URLField(default=b'', max_length=2048, verbose_name='Home url', blank=True)),
                ('auth_uri', models.URLField(max_length=2048, verbose_name='authentication uri')),
                ('token_uri', models.URLField(max_length=2048, verbose_name='token uri')),
                ('logout_uri', models.URLField(max_length=2048, verbose_name='logout uri', blank=True)),
                ('revoke_uri', models.URLField(max_length=2048, verbose_name='revoke uri', blank=True)),
                ('userinfo_uri', models.URLField(max_length=2048, verbose_name='userinfo uri', blank=True)),
                ('cert_uri', models.URLField(max_length=2048, verbose_name='certificate uri', blank=True)),
                ('profile_uri', models.URLField(default=b'', max_length=2048, verbose_name='uri for HTML View to change the profile', blank=True)),
                ('is_supporting_http_auth_header', models.BooleanField(default=True, verbose_name='is supporting http auth header')),
            ],
            options={
                'ordering': ['name'],
                'verbose_name': 'Identity Provider',
                'verbose_name_plural': 'Identity Providers',
            },
            bases=(models.Model,),
        ),
        migrations.CreateModel(
            name='IdToken',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('aud', models.CharField(max_length=255, verbose_name='audience')),
                ('email', models.CharField(max_length=255, verbose_name='email', blank=True)),
                ('exp', models.IntegerField(verbose_name='expires at')),
                ('iat', models.IntegerField(verbose_name='issued at')),
                ('iss', models.CharField(max_length=255, verbose_name='issuer')),
                ('sub', models.CharField(max_length=255, verbose_name='subject')),
                ('scope', models.CharField(max_length=2048, verbose_name='scope', blank=True)),
                ('content', models.TextField(verbose_name='JSON content')),
                ('expires_at', models.DateTimeField(verbose_name='expires at date time')),
                ('client', models.ForeignKey(to='oauth2.Client', on_delete=models.CASCADE)),
                ('user', models.ForeignKey(to=settings.AUTH_USER_MODEL, on_delete=models.CASCADE)),
            ],
            options={
                'get_latest_by': 'expires_at',
                'verbose_name': 'ID Token',
                'verbose_name_plural': 'ID Tokens',
            },
            bases=(models.Model,),
        ),
        migrations.CreateModel(
            name='Nonce',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('value', models.CharField(default=django.utils.crypto.get_random_string, max_length=12, verbose_name='value', db_index=True)),
                ('timestamp', models.DateTimeField(auto_now_add=True)),
                ('client', models.ForeignKey(to='oauth2.Client', on_delete=models.CASCADE)),
            ],
            options={
                'get_latest_by': 'timestamp',
            },
            bases=(models.Model,),
        ),
        migrations.CreateModel(
            name='Organisation',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('name', models.CharField(max_length=255, verbose_name='name')),
                ('uuid', models.CharField(unique=True, max_length=36, verbose_name='uuid')),
            ],
            options={
            },
            bases=(models.Model,),
        ),
        migrations.CreateModel(
            name='RefreshToken',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('token', models.CharField(max_length=2048, verbose_name='token')),
                ('access_token', models.OneToOneField(related_name='refresh_token', to='oauth2.AccessToken', on_delete=models.CASCADE)),
            ],
            options={
            },
            bases=(models.Model,),
        ),
        migrations.CreateModel(
            name='Role',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('group', models.OneToOneField(to='auth.Group', on_delete=models.CASCADE)),
            ],
            options={
            },
            bases=(models.Model,),
        ),
        migrations.AddField(
            model_name='client',
            name='identity_provider',
            field=models.ForeignKey(to='oauth2.IdentityProvider', on_delete=models.CASCADE),
            preserve_default=True,
        ),
        migrations.AlterUniqueTogether(
            name='client',
            unique_together=set([('identity_provider', 'type')]),
        ),
        migrations.AddField(
            model_name='apiclient',
            name='identity_provider',
            field=models.ForeignKey(to='oauth2.IdentityProvider', on_delete=models.CASCADE),
            preserve_default=True,
        ),
        migrations.AlterUniqueTogether(
            name='apiclient',
            unique_together=set([('identity_provider', 'client_id')]),
        ),
        migrations.AddField(
            model_name='accesstoken',
            name='client',
            field=models.ForeignKey(to='oauth2.Client', on_delete=models.CASCADE),
            preserve_default=True,
        ),
        migrations.AddField(
            model_name='accesstoken',
            name='user',
            field=models.ForeignKey(to=settings.AUTH_USER_MODEL, on_delete=models.CASCADE),
            preserve_default=True,
        ),
        migrations.AddField(
            model_name='user',
            name='identity_provider',
            field=models.ForeignKey(blank=True, to='oauth2.IdentityProvider', null=True, on_delete=models.CASCADE),
            preserve_default=True,
        ),
        migrations.AddField(
            model_name='user',
            name='organisations',
            field=models.ManyToManyField(to='oauth2.Organisation', null=True, blank=True),
            preserve_default=True,
        ),
        migrations.AddField(
            model_name='user',
            name='user_permissions',
            field=models.ManyToManyField(related_query_name='user', related_name='user_set', to='auth.Permission', blank=True, help_text='Specific permissions for this user.', verbose_name='user permissions'),
            preserve_default=True,
        ),
        migrations.AlterUniqueTogether(
            name='user',
            unique_together=set([('uuid', 'identity_provider')]),
        ),
    ]
