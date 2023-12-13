from django.contrib.auth.models import User
from rest_framework import viewsets
from .models import User, Role, UserRoles, Event, Log, UserData, PhoneNumbers, UserContact, UserLoginHistory
from .serializers import ( UserSerializer, RoleSerializer, UserRolesSerializer, EventSerializer, LogSerializer, UserDataSerializer,
                           PhoneNumbersSerializer, UserContactSerializer, UserLoginHistorySerializer
)

class UserViewSet(viewsets.ModelViewSet):
    serializer_class = UserSerializer

    def get_queryset(self):
        # Sprawdź, czy podano parametr ID w zapytaniu
        user_id = self.kwargs.get('pk')

        if user_id:
            return User.objects.filter(pk=user_id)
        else:
            return User.objects.all()
    
class RoleViewSet(viewsets.ModelViewSet):
    queryset = Role.objects.all()
    serializer_class = RoleSerializer

class UserRolesViewSet(viewsets.ModelViewSet):
    queryset = UserRoles.objects.all()
    serializer_class = UserRolesSerializer

class EventViewSet(viewsets.ModelViewSet):
    queryset = Event.objects.all()
    serializer_class = EventSerializer

class LogViewSet(viewsets.ModelViewSet):
    queryset = Log.objects.all()
    serializer_class = LogSerializer

class UserDataViewSet(viewsets.ModelViewSet):
    queryset = UserData.objects.all()
    serializer_class = UserDataSerializer

class PhoneNumbersViewSet(viewsets.ModelViewSet):
    queryset = PhoneNumbers.objects.all()
    serializer_class = PhoneNumbersSerializer

class UserContactViewSet(viewsets.ModelViewSet):
    queryset = UserContact.objects.all()
    serializer_class = UserContactSerializer

class UserLoginHistoryViewSet(viewsets.ModelViewSet):
    queryset = UserLoginHistory.objects.all()
    serializer_class = UserLoginHistorySerializer