# Generated by Django 2.2.17 on 2021-01-31 10:26

from django.db import migrations, models
import django.utils.timezone


class Migration(migrations.Migration):

    dependencies = [
        ('oauth2', '0034_client_roles_claim'),
    ]

    operations = [
        migrations.AlterModelOptions(
            name='accesstoken',
            options={'get_latest_by': 'created_at'},
        ),
        migrations.AddField(
            model_name='accesstoken',
            name='created_at',
            field=models.DateTimeField(auto_now_add=True, default=django.utils.timezone.now, verbose_name='created at'),
            preserve_default=False,
        ),
    ]
