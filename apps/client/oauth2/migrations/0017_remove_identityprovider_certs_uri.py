# -*- coding: utf-8 -*-
# Generated by Django 1.11.6 on 2017-11-01 21:17
from __future__ import unicode_literals

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('oauth2', '0016_auto_20170519_2341'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='identityprovider',
            name='certs_uri',
        ),
    ]
