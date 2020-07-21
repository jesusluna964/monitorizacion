from rest_framework import serializers
from Serviciosapp import models

class monitoreoSerializer(serializers.Serializer):
	porcentaje_cpu = serializers.CharField(max_length=10)
	porcentaje_memoria = serializers.CharField(max_length=10)
	porcentaje_disco = serializers.CharField(max_length=10)


