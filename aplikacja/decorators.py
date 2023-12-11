from functools import wraps
from django.http import HttpResponseForbidden

#przyznaj dostep dla uzytkownikow z rola admin,office_employee
def add_or_delete_permission(view_func):
    @wraps(view_func)
    def _wrapped_view(request, *args , **kwargs):
        if request.user.is_authenticated and (
            request.user.userroles_set.filter(role__role_name='admin').exists() or
            request.user.userroles_set.filter(role__role_name='office_employee').exists()
        ):
            return view_func(request, *args , **kwargs)
        else:
            return HttpResponseForbidden("Brak wymaganych uprawnień")
    return _wrapped_view

#przyznaj dostep dla wszystkich oprocz marketing_team_employee
def view_permission(view_func):
    @wraps(view_func)
    def _wrapped_view(request, *args , **kwargs):
        if request.user.is_authenticated and (
                request.user.userroles_set.filter(role__role_name='marketing_team_employee').exists() 
        ):
            return HttpResponseForbidden("Brak wymaganych uprawnień")
        else:
            return view_func(request, *args , **kwargs)
    return _wrapped_view