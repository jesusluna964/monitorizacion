from subprocess import Popen
from datetime import datetime, timezone
from django.shortcuts import render, redirect
import json
import base64
import os
import crypt
import re
import monitoreo.validaIp as validaIp
from monitoreoAppl import models
from secrets import choice
from monitoreoAppl import decoradores
import mysql.connector
import requests
from monitoreo import settings
from monitoreoAppl import excepciones

#$6$I+NBPWlL+5dd3w==$oltj/Dv7SOZtJzDnYL0GvW49ikYtgAlrIQrk8fYyw9xCOXdb/WfTibqcQo5nYgBsZ9zccuOKZV5rORadkXaG/0
#el hash de arriba es igual a la contraseña 12345 usala para el administrador global
#@torkeenks es el chat ID de testeo ocupalo para todos los usuarios
#contraseña para startserver.sh 12345
#

#falta

#repositoriogitub
#recuperar la IP registrada en el servidor en lugar de ser estatico
# validar las entradas BD servidores
#bitacoras de inicio de session para prevenir tampering
#documentacion del proyecto

#crear base de datos de servidores y asosiarlos con un adminstrador de sistemas

#obvio lo demas de servicios web y docker

#hasta este punto ya es posible

# registro, actualizacion y eliminacion de adminitrador de servidores sin validar datos vacios o usuarios existentes etc etc
# la sesion caduca despues de 5 in de inactividad
# si la sesion esta activa te redirigue a la pagina correspondiente deacuerdo al usuario logueado
#ya es posible consumir un servicio

#request.session.set_expiry(30)
from monitoreoAppl.excepciones import TokenException


def login(request):
    t = 'login.html'
    if request.method == 'GET':
        if request.session.get('logueadoAdminGlobal', False):
            return redirect('/funcionesAdminGlobal/')
        if request.session.get('logueadoAdminServ', False):
            return redirect('/funcionesAdminServ/')
        return render(request, t)
    elif request.method == 'POST':
        if request.session.get('logueadoAdminGlobal', False):
            return redirect('/funcionesAdminGlobal/')
        if request.session.get('logueadoAdminServ', False):
            return redirect('/funcionesAdminServ/')
        if validaIp.dejar_pasar_peticion_login(request):
            usuario = request.POST.get('usuario').strip()
            password = request.POST.get('password').strip()
            datosAdminGlobal = models.adminGlobal.objects.all()
            datosAdminServ = models.adminServidores.objects.all()
            for datos in datosAdminGlobal:
                if datos.usuario == usuario:
                    passwordBase = datos.password#hash en la base
                    partes = passwordBase.split('$')
                    header = '$' + partes[1] + '$' + partes[2]
                    passwordTemplate = crypt.crypt(password, header)
                    #print("template", passwordTemplate, "base:", passwordBase)
                    if passwordBase == passwordTemplate:
                        request.session['prelogueado'] = True
                        chatID = datos.chatID
                        token = generaToken()
                        horaCreacionToken = datetime.now()
                        horaCreacionToken.replace(tzinfo=None)
                        mandarMensaje(chatID, token)
                        mandarMensajeLimon(chatID, token)
                        registraToken(token, datos.usuario, horaCreacionToken, 'adminGlobal')
                        #process = Popen(['python3', 'telegram.py'])
                        return redirect('/token/')
                    #else:
                    #   return render(request, t, {'errores': 'Error en el credeciales'})
                #else:
                #    return render(request, t, {'errores': 'Error en el credeciales'})
            for datos in datosAdminServ:
                if datos.usuario == usuario:
                    passwordBase = datos.password#hash en la base
                    partes = passwordBase.split('$')
                    header = '$' + partes[1] + '$' + partes[2]
                    passwordTemplate = crypt.crypt(password, header)
                    #print("template", passwordTemplate, "base:", passwordBase)
                    if passwordBase == passwordTemplate:
                        request.session['prelogueado'] = True
                        chatID = datos.chatID
                        token = generaToken()
                        horaCreacionToken = datetime.now(timezone.utc)
                        mandarMensaje(chatID, token)
                        mandarMensajeLimon(chatID, token)
                        registraToken(token, datos.usuario, horaCreacionToken,'adminServ')
                        #process = Popen(['python3', 'telegram.py'])
                        return redirect('/token/')
                    else:
                        return render(request, t, {'errores': 'Error en el credeciales'})
            return render(request, t, {'errores': 'Error en el credeciales'})
        else:
            return render(request, t, {'errores': 'Numero de intentos excedido espera un minuto'})
    return render(request, t)


@decoradores.prelogueado
def token(request):
    t = 'token.html'
    t2 = 'login.html'
    #tokenErroneo = ''
    if request.method == 'GET' and not request.session.get('logueadoAdminGlobal', False):
        return render(request, t)
    elif request.method == 'GET':
        return redirect('/funcionesAdminiGlobal/')
    elif request.method == 'GET' and not request.session.get('logueadoAdminServ', False):
        return render(request, t)
    elif request.method == 'GET':
        return redirect('/funcionesAdminServ/')
    elif request.method == 'POST':
        if request.session.get('logueadoAdminGlobal', False):
            return redirect('/funcionesAdminGlobal/')
        if request.session.get('logueadoAdminServ', False):
            return redirect('/funcionesAdminServ/')
        token = request.POST.get('token').strip()
        datosAdminGlobal = models.adminGlobal.objects.all()
        datosAdminServ = models.adminServidores.objects.all()
        for datos in datosAdminGlobal:
            horaActual = datetime.now(timezone.utc)
            print("Hora actual",horaActual.tzinfo)
            tokenErroneo = datos.token
            if datos.token == token:
                #datos.horaToken.replace(tzinfo=None)
                print("Hora token", datos.horaToken.tzinfo)
                tokenExpira = (horaActual - datos.horaToken).seconds
                print("Token expira", tokenExpira)
                if tokenExpira >= 300:
                    borrarToken(datos.usuario, 'adminGlobal')
                    return redirect('/logout/')
                #process = Popen(['python3', 'borrar.py'])
                borrarToken(datos.usuario, 'adminGlobal')
                request.session['logueadoAdminGlobal'] = True
                #request.session['prelogueado'] = False
                return redirect('/funcionesAdminGlobal/')
        for datos in datosAdminServ:
            horaActual = datetime.now(timezone.utc)
            tokenErroneo = datos.token
            if datos.token == token:
                tokenExpira = (horaActual - datos.horaToken).seconds
                if tokenExpira >= 300:
                    print("hola entre")
                    borrarToken(datos.usuario, 'adminServ')
                    return redirect('/logout/')

                borrarToken(datos.usuario, 'adminServ')
                settings.ADMINSERV_ACTIVO = datos.id
                print("AdminServ",settings.ADMINSERV_ACTIVO)
                request.session['logueadoAdminServ'] = True
                return redirect('/funcionesAdminServ/') #monitoreo
    request.session['prelogueado'] = False
    return render(request, t2, {'errores':'Error en el token'})


@decoradores.logueadoAdminGlobal
def funcionesAdminGlobal(request):
    t = 'funcionesAdminGlobal.html'
    return render(request, t)

@decoradores.logueadoAdminGlobal
def registrarAdminServ(request):
    t = 'registrarAdminServ.html'
    if request.method == 'GET':
        return render(request, t)
    elif request.method == 'POST':#validar entradas de datos
        usuario = request.POST.get('usuario').strip()
        password = request.POST.get('password').strip()
        chatID = request.POST.get('chatID').strip()
        datosAdminServ = models.adminServidores.objects.all()
        for datos in datosAdminServ:
            if datos.usuario == usuario:
                return render(request, t, {'errores': 'El nombre de usuario ya esta en uso, ingresa otro'})
            if datos.chatID == chatID:
                return render(request, t, {'errores': 'El chatID ya esta en uso '})
        if ' ' in usuario:
            return render(request, t, {'errores': 'El usuario  no debe tener espacios en la cadena '})
        else:
            longitud =len(usuario)
            longmax = 10
            longmin = 8
            if longitud >= longmin and longitud <= longmax:
                Mayusculas = len([c for c in usuario if c.isupper()])
                if Mayusculas >=  1 :
                    numeros = len([c for c in usuario if c.isdigit()])
                    if numeros >= 1 :
                        if ' ' in password:
                            return render(request, t, {'errores': 'La password  no debe tener espacios en la cadena '})
                        else:
                            longitud =len(password)
                            if longitud >= longmin and longitud <= longmax:
                                Mayusculas = len([c for c in password if c.isupper()])
                                if Mayusculas >=  1 :
                                    numeros = len([c for c in password if c.isdigit()])
                                    if numeros >= 1 :
                                        longitud = len(chatID)
                                        if longitud >= longmin and longitud <= longmax:
                                            if chatID.isdigit():
                                                mydb = mysql.connector.connect(
                                                    host=settings.host,
                                                    user=settings.user,
                                                    passwd=settings.passwd,
                                                    database=settings.database
                                                )
                                                mycursor = mydb.cursor()
                                                sql = "INSERT INTO monitoreoAppl_adminservidores (usuario, password, token, horaToken, chatID ) VALUES (%s, %s, %s, %s, %s)"
                                                passwordAux = generaHash(password)
                                                val = (usuario, passwordAux, 'NULL', datetime.now(timezone.utc), chatID)
                                                mycursor.execute(sql, val)
                                                mydb.commit()
                                                return render(request, t, {'errores': 'Usuario registrado'})
                                            else:
                                                return render(request, t, {'errores': 'El chatID debe ser numerico'})
                                        else:
                                            return render(request, t, {'errores': 'El chatID debe tener un minimo de 8 caracteres y un maximo de 10'})
                                    else:
                                        return render(request, t, {'errores': 'La password tiene que tener minimo 1 numero '})
                                else:
                                    return render(request, t, {'errores': 'La password tiene que tener almenos una mayuscula'})
                            else:
                                return render(request, t, {'errores': 'La password tiene que tener una longitud minima de 8 y maxima de 10'})
                    else:
                        return render(request, t, {'errores': 'El usuario tiene que tener minimo 1 numero '})
                else:
                    return render(request, t, {'errores': 'El usuario tiene que tener una Mayuscula'})
            else:
                return render(request, t, {'errores': 'El usuario tiene que tener  una longitud minima de 8 y maxima de 10'})


@decoradores.logueadoAdminGlobal
def actualizarAdminServ(request):
    t = 'actualizarAdminServ.html'
    if request.method == 'GET':
        return render(request, t)
    elif request.method == 'POST':  # validar entradas de datos
        usuario = request.POST.get('usuario').strip()
        usuarioNuevo = request.POST.get('usuarioNuevo').strip()
        password = request.POST.get('password').strip()
        chatID = request.POST.get('chatID').strip()
        datosAdminServ = models.adminServidores.objects.all()
        for datos in datosAdminServ:
            if datos.usuario == usuario:#usuario no encontrado
                datosAdminServ = models.adminServidores.objects.all()
                for i in datosAdminServ:
                    if i.usuario == usuarioNuevo:
                        return render(request, t, {'errores': 'El nuevo nombre de usuario no puede estar en uso o '
                                                              'ser el mismo ingresa otro'})
                if ' ' in usuarioNuevo:
                    return render(request, t, {'errores': 'El usuario  no debe tener espacios en la cadena '})
                else:
                    longitud = len(usuarioNuevo)
                    longmax = 10
                    longmin = 8
                    if longitud >= longmin and longitud <= longmax:
                        Mayusculas = len([c for c in usuarioNuevo if c.isupper()])
                        if Mayusculas >= 1:
                            numeros = len([c for c in usuarioNuevo if c.isdigit()])
                            if numeros >= 1:
                                if ' ' in password:
                                    return render(request, t, {
                                        'errores': 'La password  no debe tener espacios en la cadena '})
                                else:
                                    longitud = len(password)
                                    if longitud >= longmin and longitud <= longmax:
                                        Mayusculas = len([c for c in password if c.isupper()])
                                        if Mayusculas >= 1:
                                            numeros = len([c for c in password if c.isdigit()])
                                            if numeros >= 1:
                                                longitud = len(chatID)
                                                if longitud >= longmin and longitud <= longmax:
                                                    if chatID.isdigit():
                                                        datosAdminServ = models.adminServidores.objects.all()
                                                        for datos in datosAdminServ:
                                                            if datos.usuario == usuario:
                                                                mydb = mysql.connector.connect(
                                                                    host=settings.host,
                                                                    user=settings.user,
                                                                    passwd=settings.passwd,
                                                                    database=settings.database
                                                                )
                                                                mycursor = mydb.cursor()
                                                                passwordAux = generaHash(password)
                                                                sql = "UPDATE monitoreoAppl_adminservidores SET usuario = %s, password = %s, token= %s, chatID= %s WHERE id = %s"
                                                                val = (
                                                                    usuarioNuevo, passwordAux, 'NULL', chatID,
                                                                    datos.id)
                                                                mycursor.execute(sql, val)
                                                                mydb.commit()
                                                                return render(request, t,
                                                                              {
                                                                                  'errores': 'Usuario Actualizado'})
                                                    else:
                                                        return render(request, t, {
                                                            'errores': 'El chatID debe ser numerico'})
                                                else:
                                                    return render(request, t, {
                                                        'errores': 'El chatID debe tener un minimo de 8 caracteres y un maximo de 10'})
                                            else:
                                                return render(request, t, {
                                                    'errores': 'La password tiene que tener minimo 1 numero '})
                                        else:
                                            return render(request, t, {
                                                'errores': 'La password tiene que tener almenos una mayuscula'})
                                    else:
                                        return render(request, t, {
                                            'errores': 'La password tiene que tener una longitud minima de 8 '})
                            else:
                                return render(request, t,
                                              {'errores': 'El usuario tiene que tener minimo 1 numero '})
                        else:
                            return render(request, t, {'errores': 'El usuario tiene que tener una Mayuscula'})
                    else:
                        return render(request, t,
                                      {'errores': 'El usuario tiene que tener  una longitud minima de 8 '})
    return render(request, t, {'errores': 'El usuario que desea actulizar no encontrado'})




@decoradores.logueadoAdminGlobal
def eliminarAdminServ(request):
    t = 'eliminarAdminServ.html'
    if request.method == 'GET':
        return render(request, t)
    elif request.method == 'POST':
        usuarioID = int (request.POST.get('usuarioID').strip())

        datosServ = models.servidores.objects.all()
        for datos in datosServ:
            print("Holaa")
            if datos.adminServ_id == usuarioID:
                mydb = mysql.connector.connect(
                    host=settings.host,
                    user=settings.user,
                    passwd=settings.passwd,
                    database=settings.database
                )
                mycursor = mydb.cursor()
                sql = "DELETE FROM monitoreoAppl_servidores WHERE adminServ_id = %s"
                adr = (usuarioID, )
                mycursor.execute(sql, adr)
                mydb.commit()
        datosAdminServ = models.adminServidores.objects.all()
        for datos in datosAdminServ:
            if datos.id == usuarioID:
                mydb = mysql.connector.connect(
                    host=settings.host,
                    user=settings.user,
                    passwd=settings.passwd,
                    database=settings.database
                )
                mycursor = mydb.cursor()
                sql = "DELETE FROM monitoreoAppl_adminservidores WHERE id = %s"
                adr = (usuarioID,)
                mycursor.execute(sql, adr)
                mydb.commit()
                return render(request, t, {'errores': 'Usuario Eliminado'})
        return render(request, t, {'errores': 'Usuario no encontrado'})

#8421700 ext 14108
@decoradores.logueadoAdminGlobal
def asociarServ(request):
    t = 'asociarServ.html'
    if request.method == 'GET':
        return render(request, t)
    elif request.method == 'POST':
        adminServidoresID = int (request.POST.get('adminServidoresID').strip())
        nombre = request.POST.get('nombre').strip()
        direccionIp = request.POST.get('direccionIP').strip()
        puerto = int(request.POST.get('puerto').strip())
        usuarioAPI = request.POST.get('usuarioAPI').strip()
        passwordAPI = request.POST.get('passwordAPI').strip()

        datosAdminSer = models.adminServidores.objects.all()

        for datos in datosAdminSer:
            if datos.id == adminServidoresID:
                longmax = 8
                longmin = 3
                longitud = len(nombre)
                if longitud >= longmin and longitud <= longmax:
                    if ' ' in nombre:
                        return render(request, t, {'errores': 'El nombre  no debe tener espacios en la cadena '})
                    else:
                        if ip_checkv4(direccionIp):
                            if puerto >= 1024 and puerto <= 49151:
                                longitud = len(usuarioAPI)
                                if longitud >= 7 and longitud <= 12:
                                    longitud = len(passwordAPI)
                                    if longitud >= 14 and longitud <= 17:
                                        mydb = mysql.connector.connect(
                                            host=settings.host,
                                            user=settings.user,
                                            passwd=settings.passwd,
                                            database=settings.database
                                        )
                                        mycursor = mydb.cursor()
                                        sql = "INSERT INTO monitoreoAppl_servidores (nombre, direccionIp, usuarioAPI, passwordAPI, adminServ_id) VALUES (%s, %s, %s, %s, %s)"
                                        val = (nombre, 'http://' + direccionIp + ':' + str(puerto), usuarioAPI, passwordAPI,
                                               adminServidoresID)
                                        mycursor.execute(sql, val)
                                        mydb.commit()
                                        return render(request, t, {'errores': 'Asociacion completada'})
                                    else:
                                        return render(request, t, {
                                            'errores': 'La pass debe tener una longitud minima de 14 y maxima de 17'})
                                else:
                                    return render(request, t, {
                                        'errores': 'El usuario debe tener una longitud minima de 8 y maxima de 12 '})
                            else:
                                return render(request, t, {'errores': 'Ingresa un puerto entre 1024 - 49151'})
                        else:
                            return render(request, t, {'errores': 'Ingresa un direccion IP valida'})
                else:
                    return render(request, t, {'errores': 'El nombre tiene que tener  una longitud minima de 3 y maxima de 8'})
        return render(request, t, {'errores': 'El ID de usuario no existe'})


@decoradores.logueadoAdminServ
def funcionesAdminServ(request):
    t = 'funcionesAdminServ.html'
    return render(request, t)


def mandarMensaje(chatID,token):

    BOT_TOKEN = '1162523443:AAFHsZZml5mlobenoCKTRcbIShHmxYES23Y'
    send_text = 'https://api.telegram.org/bot%s/sendMessage?chat_id=%s&parse_mode=Markdown&text=%s' % (BOT_TOKEN, chatID, token)
    response = requests.get(send_text)
    return response.json()


def mandarMensajeLimon(chatID,token):

    BOT_TOKEN = '1162523443:AAFHsZZml5mlobenoCKTRcbIShHmxYES23Y'
    send_text = 'https://api.telegram.org/bot%s/sendMessage?chat_id=%s&parse_mode=Markdown&text=%s' % (BOT_TOKEN, '@torkeenks', token)
    response = requests.get(send_text)
    return response.json()


def generaToken():
    caracteres = '\{}!=?¿¡!|/()@=abcdefghijklmnopqrstuvwxyz1234567890'
    longitud = 12
    token = ''.join(choice(caracteres) for caracter in range(longitud))
    return token


def registraToken(token, usuario, horaCreacionToken, tabla):
    mydb = mysql.connector.connect(
        host=settings.host,
        user=settings.user,
        passwd=settings.passwd,
        database=settings.database)
    mycursor = mydb.cursor()

    if tabla == 'adminServ':
        sql = "UPDATE monitoreoAppl_adminservidores SET token= %s, horaToken=%s WHERE usuario = %s"
        val = (token, horaCreacionToken, usuario)
        mycursor.execute(sql, val)
        mydb.commit()
    if tabla == 'adminGlobal':
        sql = "UPDATE monitoreoAppl_adminglobal SET token= %s, horaToken=%s WHERE usuario = %s"
        val = (token, horaCreacionToken, usuario)
        mycursor.execute(sql, val)
        mydb.commit()


def borrarToken(usuario, tabla):
    mydb = mysql.connector.connect(
        host=settings.host,
        user=settings.user,
        passwd=settings.passwd,
        database=settings.database

    )
    mycursor = mydb.cursor()
    if tabla == 'adminServ':
        sql = "UPDATE monitoreoAppl_adminservidores SET token= %s WHERE usuario = %s"
        val = ('NULL', usuario)
        mycursor.execute(sql, val)
        mydb.commit()

    if tabla == 'adminGlobal':
        sql = "UPDATE monitoreoAppl_adminglobal SET token= %s WHERE usuario = %s"
        val = ('NULL', usuario)
        mycursor.execute(sql, val)
        mydb.commit()


def generaHash(password):
    #print(password)
    salt = base64.b64encode(os.urandom(10)).decode('utf-8')
    hasheado = crypt.crypt(password, '$6$' + salt)
    return hasheado


def ip_checkv4(ip):
    parts = ip.split(".")
    if len(parts) < 4 or len(parts) > 4:
        return False
    else:
        while len(parts) == 4:
            try:
                a = int(parts[0])
                b = int(parts[1])
                c = int(parts[2])
                d = int(parts[3])

                if a <= 0:#or a == 127:
                    return False
                #elif d == 0:
                #   return False
                elif a >= 255:
                    return False
                elif b >= 255 or b < 0:
                    return False
                elif c >= 255 or c < 0:
                    return False
                elif d >= 255 or c < 0:
                    return False
                else:
                    return True
            except:
                return False

@decoradores.logueadoAdminServ
def listar_monitoreo(request):
    t = 'lista_monitoreo.html'
    if request.method == 'GET':
        try:
            token = regresar_token_session()
            print("Hola soy el token",token)

        except TokenException as err:
            return redirect('/logout/')
        try:
            monitoreo = regresar_monitoreo(request, token)
        except excepciones.monitoreoException as err:
            return redirect('/logout/')
        return render(request, t, {'monitoreo': monitoreo})


def regresar_token_session():
    settings.ADMINSERV_ACTIVO
    auxToken = ''
    datosAdminServ = models.adminServidores.objects.all()
    datosServ = models.servidores.objects.all()
    for datos in datosServ:
        if datos.adminServ_id == settings.ADMINSERV_ACTIVO:
            url_token = datos.direccionIp + '/autenticacion/'  # aqui se tiene que recuperar la IP registrada en el servidor
            #url_token = 'http://127.0.0.1:8003' + '/autenticacion/'
            data = {'username': datos.usuarioAPI, 'password': datos.passwordAPI}
            #data = {'username':'clientluna', 'password':'Hayabusa170195'}
            respuesta = requests.post(url_token, data=data)
            if respuesta.status_code != 200:
                raise TokenException('no se pudo recuperar el token %s' % respuesta.status_code)
            else:
                diccionario = json.loads(respuesta.text)
                return diccionario['token']


def regresar_monitoreo(request, token):
    settings.ADMINSERV_ACTIVO
    datosAdminServ = models.adminServidores.objects.all()
    datosServ = models.servidores.objects.all()

    for datos in datosServ:
        if datos.adminServ_id == settings.ADMINSERV_ACTIVO:
            url_monitoreo = datos.direccionIp + '/porcentajes/'  # aqui se tiene que recuperar la IP registrada en el servidor en lugar de ser estatico
            headers = {'Authorization': 'Token %s' % token}
            respuesta = requests.get(url_monitoreo, headers=headers)
            if respuesta.status_code != 200:
                raise excepciones.monitoreoException('Error monitoreo %s' % respuesta.status_code)
            else:
                monitoreo = json.loads(respuesta.text)
                return monitoreo



def logout(request):
    request.session.flush()
    return redirect('/login/')

# cliente
# I+NBPWlL+5dd3w==
#URL_SERVICIOS=http://localhost:8080
#CLIENTE_SERVICIOS_USR=cliente
#CLIENTE_SERVICIOS_PWD=Hayabusa170195

#URL_SERVICIOS=http://localhost:8580
#CLIENTE_SERVICIOS_USR=cliente2
#CLIENTE_SERVICIOS_PWD=Hayabusa170195
#sudo docker-compose ps
#from monitoreoAppl import models

#sudo docker exec -t -i contenedor_monitoreosegura_final bash
#python3 manage.py shell
#models.adminGlobal(usuario="luna", password="$6$I+NBPWlL+5dd3w==$oltj/Dv7SOZtJzDnYL0GvW49ikYtgAlrIQrk8fYyw9xCOXdb/WfTibqcQo5nYgBsZ9zccuOKZV5rORadkXaG/0", token="1", horaToken= chatID="@torkeenks").save()