"""
URL configuration for my_app project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.template.defaulttags import url
from django.urls import path, include
from rest_framework import permissions
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)
from aplikacja.Login_Register import register, login_view,  logout_view
from aplikacja.GoogleEvents import save_google_calendar, get_google_events, delete_event, edit_event,get_single_google_event
from drf_yasg.views import get_schema_view
from drf_yasg import openapi

schema_view = get_schema_view(
    openapi.Info(
        title="Strona z API",
        default_version='v1.0.0',
        description="Dokumentacja wszystkich API na serwerze, "
                    "Autoryzacja po wywołaniu metody login i otrzymaniu tokenu Bearer <access_token>",
    ),
    public=True,
    permission_classes=(permissions.AllowAny,),
)





urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/', include('aplikacja.urls')),

    #path('api/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),

    #logowanie
    path('login/', login_view, name='login'),
    path('register/', register, name='register'),
    path('logout/', logout_view, name='logout'),

    #GOOGLE CALENDAR
    path('save_google_calendar/', save_google_calendar, name='save_google_calendar'),
    path('get_google_events/', get_google_events, name='get_google_events'),
    path('get_single_google_event/<str:event_id>/', get_single_google_event, name='get_single_google_event'),
    path('edit_event/<str:event_id>/', edit_event , name='edit_event'),
    path('delete_event/<str:event_id>/', delete_event, name='logout'),
    
    path('swagger/', schema_view.with_ui('swagger', cache_timeout=0),name='schema-swagger-ui'),
]

