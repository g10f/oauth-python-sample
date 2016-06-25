# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('oauth2', '0006_auto_20140918_2011'),
    ]

    operations = [
        migrations.RenameField(
            model_name='identityprovider',
            old_name='user_apps_uri',
            new_name='user_navigation_uri',
        ),
    ]
