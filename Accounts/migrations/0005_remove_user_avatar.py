# Generated by Django 5.1.1 on 2024-10-06 13:37

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('Accounts', '0004_alter_user_avatar'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='user',
            name='avatar',
        ),
    ]
