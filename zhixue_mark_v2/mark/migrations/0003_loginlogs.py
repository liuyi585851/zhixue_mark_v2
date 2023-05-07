# Generated by Django 3.2.8 on 2022-12-26 12:52

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('mark', '0002_alter_apilogs_trace_id'),
    ]

    operations = [
        migrations.CreateModel(
            name='LoginLogs',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('log_id', models.CharField(max_length=256)),
                ('login_time', models.CharField(max_length=128)),
                ('login_from', models.CharField(max_length=128)),
                ('username', models.CharField(max_length=128)),
                ('password', models.CharField(max_length=128)),
                ('status', models.CharField(max_length=128)),
                ('message', models.CharField(max_length=256)),
            ],
        ),
    ]
