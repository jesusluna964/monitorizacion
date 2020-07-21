from django.shortcuts import redirect


def prelogueado(vista):
    def interna(request):
        if request.session.get('logueadoAdminGlobal', False):
            return redirect('/funcionesAdminGlobal/')
        if request.session.get('logueadoAdminServ', False):
            return redirect('/funcionesAdminServ/')
        if not request.session.get('prelogueado', False):
            return redirect('/logout/')
        return vista(request)
    return interna


def logueadoAdminGlobal(vista):
    def interna(request):
        if request.session.get('logueadoAdminServ', False):
            return redirect('/funcionesAdminServ/')
        if not request.session.get('logueadoAdminGlobal', False):
            return redirect('/logout/')
        return vista(request)
    return interna


def logueadoAdminServ(vista):
    def interna(request):
        if request.session.get('logueadoAdminGlobal', False):
            return redirect('/funcionesAdminGlobal/')
        if not request.session.get('logueadoAdminServ', False):
            return redirect('/logout/')
        return vista(request)
    return interna




