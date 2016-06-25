# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('oauth2', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='idtoken',
            name='raw',
            field=models.TextField(default=b'', verbose_name='raw content', blank=True),
            preserve_default=True,
        ),
    ]
