# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('oauth2', '0012_identityprovider_order'),
    ]

    operations = [
        migrations.AlterModelOptions(
            name='identityprovider',
            options={'ordering': ['order', 'name'], 'verbose_name': 'Identity Provider', 'verbose_name_plural': 'Identity Providers'},
        ),
    ]
