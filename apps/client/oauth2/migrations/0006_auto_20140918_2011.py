# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('oauth2', '0005_identityprovider_user_apps_uri'),
    ]

    operations = [
        migrations.RenameField(
            model_name='identityprovider',
            old_name='auth_uri',
            new_name='authorization_endpoint',
        ),
        migrations.RenameField(
            model_name='identityprovider',
            old_name='cert_uri',
            new_name='certs_uri',
        ),
        migrations.RenameField(
            model_name='identityprovider',
            old_name='logout_uri',
            new_name='end_session_endpoint',
        ),
        migrations.RenameField(
            model_name='identityprovider',
            old_name='token_uri',
            new_name='token_endpoint',
        ),
        migrations.RenameField(
            model_name='identityprovider',
            old_name='userinfo_uri',
            new_name='userinfo_endpoint',
        ),
    ]
