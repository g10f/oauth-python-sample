# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('oauth2', '0014_auto_20150505_2220'),
    ]

    operations = [
        migrations.AddField(
            model_name='idtoken',
            name='acr',
            field=models.TextField(default=b'', verbose_name='Authentication Context Class Reference', blank=True),
        ),
    ]
