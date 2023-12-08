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
from django.urls import path, include
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)
from aplikacja.views import (register, login_view, save_google_calendar, authorize_view, get_google_events , logout_view
)

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/', include('aplikacja.urls')),
    path('api/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('login/', login_view, name='login'),
    path('register/', register, name='register'),
    path('save_google_calendar/', save_google_calendar, name='save_google_calendar'),
    path('get_google_events/', get_google_events, name='get_google_events'),
    path('authorize/', authorize_view, name='authorize'),
    path('logout/', logout_view, name='logout'),
]
