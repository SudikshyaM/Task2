# Generated by Django 5.1.1 on 2024-10-06 14:19

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('Accounts', '0006_user_avatar'),
    ]

    operations = [
        migrations.AlterField(
            model_name='user',
            name='avatar',
            field=models.ImageField(null=True, upload_to='uploads/'),
        ),
    ]