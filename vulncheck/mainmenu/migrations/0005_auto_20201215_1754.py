# Generated by Django 3.1.4 on 2020-12-15 17:54

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('mainmenu', '0004_submenu_mainmenu'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='submenu',
            name='mainmenu',
        ),
        migrations.DeleteModel(
            name='MainMenu',
        ),
        migrations.DeleteModel(
            name='SubMenu',
        ),
    ]
