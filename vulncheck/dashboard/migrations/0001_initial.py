# Generated by Django 3.1.7 on 2021-04-10 08:42

from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='Library',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('application_name', models.CharField(default=None, max_length=100)),
                ('library_list', models.FileField(upload_to='uploads/')),
                ('data_mode', models.CharField(blank=True, choices=[('', '------------'), ('application', 'Application'), ('services', 'Services'), ('windows', 'Operating System: Windows'), ('linux', 'Operating System: Linux')], default='no', max_length=100)),
                ('created_at', models.DateField(default=None)),
                ('updated_at', models.DateField(default=None)),
                ('created_by', models.IntegerField(default=None)),
            ],
        ),
    ]
