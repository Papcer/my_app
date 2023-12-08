from rest_framework import serializers
from .models import User, Role, UserRoles, Event, Log, UserData, PhoneNumbers, UserContact, UserLoginHistory

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model=User
        fields = ['id', 'username', 'password', 'last_login']
    
class RoleSerializer(serializers.ModelSerializer):
    class Meta:
        model=Role
        fields = ['id', 'role_name']

class UserRolesSerializer(serializers.ModelSerializer):
    class Meta:
        model=UserRoles
        fields = ['id', 'user', 'role']

class EventSerializer(serializers.ModelSerializer):
    class Meta:
        model=Event
        fields = ['id', 'title', 'description', 'start_date', 'end_date', 'attendees', 'city', 'zipcode', 'street']

class LogSerializer(serializers.ModelSerializer):
    class Meta:
        model = Log
        fields = ['id', 'user', 'event', 'log_type', 'log_description', 'timestamp']

class UserDataSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserData
        fields = ['id', 'user', 'name', 'surname', 'city', 'zipcode', 'street']

class PhoneNumbersSerializer(serializers.ModelSerializer):
    class Meta:
        model = PhoneNumbers
        fields = ['id', 'phonenumber']

class UserContactSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserContact
        fields = ['id', 'user', 'phonenumber']

class UserLoginHistorySerializer(serializers.ModelSerializer):
    class Meta:
        model = UserLoginHistory
        fields = ['id', 'user', 'login_time']