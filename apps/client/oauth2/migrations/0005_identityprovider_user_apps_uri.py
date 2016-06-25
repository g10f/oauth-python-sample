# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('oauth2', '0004_identityprovider_check_session_iframe'),
    ]

    operations = [
        migrations.AddField(
            model_name='identityprovider',
            name='user_apps_uri',
            field=models.URLField(default=b'', max_length=2048, verbose_name='user apps uri', blank=True),
            preserve_default=True,
        ),
    ]
