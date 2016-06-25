# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('oauth2', '0008_auto_20140918_2113'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='idtoken',
            name='expires_at',
        ),
        migrations.RemoveField(
            model_name='idtoken',
            name='scope',
        ),
        migrations.AddField(
            model_name='idtoken',
            name='auth_time',
            field=models.DateTimeField(null=True, verbose_name='authentication time', blank=True),
            preserve_default=True,
        ),
        migrations.AddField(
            model_name='idtoken',
            name='roles',
            field=models.CharField(default='', max_length=2048, verbose_name='roles', blank=True),
            preserve_default=False,
        ),
        migrations.RemoveField(
            model_name='idtoken',
            name='exp',
        ),
        migrations.AddField(
            model_name='idtoken',
            name='exp',
            field=models.DateTimeField(verbose_name='expires at'),
        ),
        migrations.RemoveField(
            model_name='idtoken',
            name='iat',
        ),
        migrations.AddField(
            model_name='idtoken',
            name='iat',
            field=models.DateTimeField(verbose_name='issued at'),
        ),
        migrations.AlterField(
            model_name='idtoken',
            name='session_state',
            field=models.TextField(default=b'', verbose_name='session state', blank=True),
        ),
    ]
