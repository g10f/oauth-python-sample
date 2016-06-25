# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('oauth2', '0007_auto_20140918_2112'),
    ]

    operations = [
        migrations.AlterField(
            model_name='identityprovider',
            name='user_navigation_uri',
            field=models.URLField(default=b'', max_length=2048, verbose_name='user navigation uri', blank=True),
        ),
    ]
