# Generated by Django 3.0.8 on 2020-07-12 18:30

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='adminGlobal',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('usuario', models.CharField(max_length=10)),
                ('password', models.CharField(max_length=200)),
                ('token', models.CharField(max_length=15)),
                ('horaToken', models.DateTimeField()),
                ('chatID', models.CharField(max_length=20)),
            ],
        ),
        migrations.CreateModel(
            name='adminServidores',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('usuario', models.CharField(max_length=10)),
                ('password', models.CharField(max_length=200)),
                ('token', models.CharField(max_length=15)),
                ('horaToken', models.DateTimeField()),
                ('chatID', models.CharField(max_length=20)),
            ],
        ),
        migrations.CreateModel(
            name='ip',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('ip', models.GenericIPAddressField(unique=True)),
                ('ultima_peticion', models.DateTimeField()),
                ('intentos', models.IntegerField(default=0)),
            ],
        ),
        migrations.CreateModel(
            name='servidores',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('nombre', models.CharField(max_length=10)),
                ('direccionIp', models.CharField(max_length=15)),
                ('usuarioAPI', models.CharField(max_length=25)),
                ('passwordAPI', models.CharField(max_length=25)),
                ('adminServidores', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='monitoreoAppl.adminServidores')),
            ],
        ),
    ]
