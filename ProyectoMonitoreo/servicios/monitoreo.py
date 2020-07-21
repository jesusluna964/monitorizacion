import psutil,os, json

# Indicamos la ruta del disco.
disk_usage = psutil.disk_usage("/")
memory = psutil.virtual_memory()
CPU = psutil.cpu_percent(interval=1)
def to_gb(bytes):
    "Convierte bytes a gigabytes."
    return bytes / 1024**3

disco_usado = format(to_gb(disk_usage.used))
print("Porcentaje de espacio usado: {}%.".format(disk_usage.percent))
memoria_usada=format(memory.percent)
cpu_usado=format(CPU)

disco ={'disco usado: %s' % disco_usado}
memoria={'memoria usado: %s' % memoria_usada}
cpu ={'cpu_ usado: %s' % cpu_usado}

print(disco,memoria,cpu)