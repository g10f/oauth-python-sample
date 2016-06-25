# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('oauth2', '0002_idtoken_raw'),
    ]

    operations = [
        migrations.AddField(
            model_name='idtoken',
            name='session_state',
            field=models.TextField(default=b'', verbose_name='raw content', blank=True),
            preserve_default=True,
        ),
    ]
