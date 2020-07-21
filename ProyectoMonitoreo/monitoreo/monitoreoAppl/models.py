from django.db import models

# Create your models here.
from django.db import models


class ip(models.Model):
    ip = models.GenericIPAddressField(null=False, blank=False, unique=True)
    ultima_peticion = models.DateTimeField(null=False, blank=False)
    intentos = models.IntegerField(null=False, blank=False, default=0)


class adminGlobal(models.Model):
    usuario = models.CharField(max_length=10)
    password = models.CharField(max_length=200)
    token = models.CharField(max_length=15)
    horaToken = models.DateTimeField(null=False, blank=False)
    chatID = models.CharField(max_length=20)


class adminServidores(models.Model):
    usuario = models.CharField(max_length=10)
    password = models.CharField(max_length=200)
    token = models.CharField(max_length=15)
    horaToken = models.DateTimeField(null=False, blank=False)
    chatID = models.CharField(max_length=20)
    # asosiacion un administarador por servidor
    # llave foranea hacia administrador de servidor

class servidores(models.Model):
    adminServ = models.ForeignKey(adminServidores, on_delete=models.CASCADE)
    nombre = models.CharField(max_length=10)
    direccionIp = models.CharField(max_length=25)
    usuarioAPI = models.CharField(max_length=25)
    passwordAPI = models.CharField(max_length=25)
