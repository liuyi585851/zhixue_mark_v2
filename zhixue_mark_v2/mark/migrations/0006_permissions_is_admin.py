# Generated by Django 3.2.8 on 2023-01-22 05:23

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('mark', '0005_permissions'),
    ]

    operations = [
        migrations.AddField(
            model_name='permissions',
            name='is_admin',
            field=models.BooleanField(default=0),
            preserve_default=False,
        ),
    ]
