# Generated by Django 2.0.5 on 2018-08-03 12:56

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('oauth2', '0023_auto_20180801_1349'),
    ]

    operations = [
        migrations.AddField(
            model_name='client',
            name='response_type',
            field=models.CharField(blank=True, max_length=255, verbose_name='response type'),
        ),
    ]