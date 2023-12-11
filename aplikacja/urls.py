# myapp/urls.py
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import (
    UserViewSet, RoleViewSet, UserRolesViewSet,
    EventViewSet, LogViewSet, UserDataViewSet,
    PhoneNumbersViewSet, UserContactViewSet, UserLoginHistoryViewSet,
)

router = DefaultRouter()
router.register(r'users', UserViewSet, basename='user')
router.register(r'roles', RoleViewSet)
router.register(r'userroles', UserRolesViewSet)
router.register(r'events', EventViewSet)
router.register(r'logs', LogViewSet)
router.register(r'userdata', UserDataViewSet)
router.register(r'phonenumbers', PhoneNumbersViewSet)
router.register(r'usercontacts', UserContactViewSet)
router.register(r'userloginhistory', UserLoginHistoryViewSet)

urlpatterns = [
    path('', include(router.urls)),

]