# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('oauth2', '0003_idtoken_session_state'),
    ]

    operations = [
        migrations.AddField(
            model_name='identityprovider',
            name='check_session_iframe',
            field=models.URLField(default=b'', max_length=2048, verbose_name='check_session_iframe uri', blank=True),
            preserve_default=True,
        ),
    ]
