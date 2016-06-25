# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('oauth2', '0011_identityprovider_is_active'),
    ]

    operations = [
        migrations.AddField(
            model_name='identityprovider',
            name='order',
            field=models.IntegerField(default=0, help_text='Overwrites the alphabetic order.'),
            preserve_default=True,
        ),
    ]
