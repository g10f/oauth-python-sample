# Generated by Django 2.2.9 on 2020-01-19 11:52

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('oauth2', '0028_auto_20200119_0003'),
    ]

    operations = [
        migrations.AlterField(
            model_name='accesstoken',
            name='token',
            field=models.CharField(max_length=8192, verbose_name='token'),
        ),
    ]