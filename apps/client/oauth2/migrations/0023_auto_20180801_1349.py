# Generated by Django 2.0.5 on 2018-08-01 11:49

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('oauth2', '0022_client_use_pkce'),
    ]

    operations = [
        migrations.AddField(
            model_name='client',
            name='name',
            field=models.CharField(blank=True, max_length=255, verbose_name='name'),
        ),
        migrations.AlterField(
            model_name='identityprovider',
            name='name',
            field=models.CharField(max_length=255, unique=True, verbose_name='name'),
        ),
        migrations.AlterUniqueTogether(
            name='client',
            unique_together=set(),
        ),
    ]