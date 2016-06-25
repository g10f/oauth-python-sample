# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('oauth2', '0009_auto_20141021_0909'),
    ]

    operations = [
        migrations.AlterModelOptions(
            name='idtoken',
            options={'get_latest_by': 'exp', 'verbose_name': 'ID Token', 'verbose_name_plural': 'ID Tokens'},
        ),
        migrations.AddField(
            model_name='identityprovider',
            name='picture_endpoint',
            field=models.URLField(default=b'', max_length=2048, verbose_name='picture uri', blank=True),
            preserve_default=True,
        ),
    ]
