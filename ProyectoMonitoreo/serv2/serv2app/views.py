from django.shortcuts import render
from rest_framework.decorators import api_view, permission_classes, authentication_classes, throttle_classes
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework.authentication import TokenAuthentication
from rest_framework.throttling import UserRateThrottle
import psutil, json

@api_view(['GET'])
@authentication_classes([TokenAuthentication])
@permission_classes([IsAuthenticated])
@throttle_classes([UserRateThrottle])

def porcentajes(request):
	if request.method == 'GET':
		# Indicamos la ruta del disco.
		disk_usage = psutil.disk_usage("/")
		memory = psutil.virtual_memory()
		CPU = psutil.cpu_percent(interval=1)
		disco_usado = format(disk_usage.percent)
		memoria_usada = format(memory.percent)
		cpu_usado = format(CPU)
		datos_raw = '[{"Disco": "Porcentaje Disco %s "},{"Memoria": "Porcentaje Memoria RAM %s"},{"CPU": "Porcentaje CPU %s"}]'%(disco_usado,memoria_usada,cpu_usado)
		datos = json.loads(datos_raw)
		return Response(datos)