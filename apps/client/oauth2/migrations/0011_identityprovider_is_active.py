# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('oauth2', '0010_auto_20141123_1407'),
    ]

    operations = [
        migrations.AddField(
            model_name='identityprovider',
            name='is_active',
            field=models.BooleanField(default=True, verbose_name='is active'),
            preserve_default=True,
        ),
    ]
