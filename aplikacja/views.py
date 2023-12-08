import datetime

from argon2.exceptions import VerifyMismatchError
from django.http import JsonResponse
from django.shortcuts import render
from django.views.decorators.csrf import csrf_exempt
from google.oauth2 import service_account
from rest_framework import generics, permissions, status
from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.response import Response
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login, get_user_model, logout
from rest_framework import viewsets
import json

#google API
from rest_framework.permissions import IsAuthenticated, AllowAny
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from google.auth.transport.requests import Request

from .models import User, Role, UserRoles, Event, Log, UserData, PhoneNumbers, UserContact, UserLoginHistory
from .serializers import ( UserSerializer, RoleSerializer, UserRolesSerializer, EventSerializer, LogSerializer, UserDataSerializer, 
                           PhoneNumbersSerializer, UserContactSerializer, UserLoginHistorySerializer
)
# Create your views here.
SCOPES = ['https://www.googleapis.com/auth/calendar.events']
TOKEN_FILE = 'aplikacja/token.json'
@api_view(['POST'])
@permission_classes([AllowAny]) #dostepne dla kazdego
@csrf_exempt
def register(request):
    if request.method == 'POST':
        username = request.data.get('username')
        password = request.data.get('password')

        if not username or not password:
            return JsonResponse({'error': 'Wymagane sa nazwa i haslo.'}, status=400)

        user = User.create_user(username=username, password=password)
        return JsonResponse({'message': 'Pomyslnie zarejestrowano uzytkownika.'}, status=201)

@api_view(['POST'])
@permission_classes([AllowAny]) #dostepne dla kazdego
@csrf_exempt
def login_view(request):
    if request.method == 'POST':
        username = request.data.get('username')
        password = request.data.get('password')

        if not username or not password:
            return JsonResponse({'error': 'Email i haslo wymagane.'}, status=400)

        user = custom_authenticate(username, password)

        if user:
            # Logowanie użytkownika
            login(request, user)

            #wszystkie role powiazanie z danym uzytkownikiem
            user_roles = UserRoles.objects.filter(user=user)
           
            roles_list = list(user_roles.values_list('role__role_name', flat=True))
            # Generowanie tokenów JWT
            refresh = RefreshToken.for_user(user)
            refresh['roles'] = roles_list
            
            return JsonResponse({
                'message': 'Poprawnie zalogowano.',
                'access_token': str(refresh.access_token),
                'refresh_token': str(refresh),
            }, status=200)
        else:
            return JsonResponse({'error': 'Bledne dane.'}, status=401)

@api_view(['POST'])
def logout_view(request):
    if request.method == 'POST':
        #usuniecie ciasteczek
        request.session.flush()
        # Wylogowanie użytkownika
        logout(request)

        return JsonResponse({'message': 'Poprawnie wylogowano.'}, status=200)
    else:
        return JsonResponse({'error': 'Bledna metoda.'}, status=405) #gdy bedzie GET
    
def custom_authenticate(username, password):
    try:
        user = User.objects.get(username=username)
        if user.check_password(password):
            return user
    except User.DoesNotExist:
        return None

#Zapis tokenu do pliku po jego otrzymaniu
def save_token_to_file(credentials):
    with open(TOKEN_FILE, 'w') as token_file:
        token_file.write(credentials.to_json())

#Zaladowanie tokenu z pliku
def load_token_from_file():
    try:
        with open(TOKEN_FILE, 'r') as token_file:
            token_data = json.load(token_file)

        return Credentials.from_authorized_user_info(token_data)
    except FileNotFoundError:
        return None

#autoryzacja z google i zapisanie do pliku
def authorize(request):
    flow = InstalledAppFlow.from_client_secrets_file(
        'aplikacja/user_credentials.json', SCOPES)
    credentials = flow.run_local_server(8080)
    save_token_to_file(credentials)

def authorize_view(request):
    return authorize(request)
    
#sprawdzenie poprawnosci tokenu
def check_for_credentials(request):
    credentials = load_token_from_file()
    if not credentials:
        # Użytkownik nie ma ważnego tokenu
        authorize(request)
        return None

    if credentials and credentials.valid:
        return credentials
    
    # Jeśli token wygasa, odśwież go
    if credentials.expired and credentials.refresh_token:
        try:
            credentials.refresh(Request())
            save_token_to_file(credentials)
            return credentials
        except Exception as refresh_error:
            return None

    authorize(request)
    return None

@api_view(['POST'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
def save_google_calendar(request):
    title = request.data.get('title')
    description = request.data.get('description')
    start_datetime = request.data.get('start_datetime')
    end_datetime = request.data.get('end_datetime')
    attendees = request.data.get('attendees')
    location = request.data.get("location")
    
    if not title or not description or not start_datetime or not end_datetime:
        return Response({'error': 'Wszystkie pola wymagane'}, status=400)

    #te metody nie dzialaja, problem z service account
    #credentials = Credentials.from_authorized_user_file('aplikacja/credentials.json', SCOPES)
    #credentials = service_account.Credentials.from_service_account_file('aplikacja/credentials.json', scopes=SCOPES)

    credentials = check_for_credentials(request)
    if not credentials:
        return Response({'error': 'Brak ważnego tokenu. Przekierowywanie do autoryzacji.'}, status=401)

    service = build('calendar', 'v3', credentials=credentials)

    event = {
        'summary': title,
        'location': location,
        'description': description,
        'start': {
            'dateTime': start_datetime,
            'timeZone': 'GMT+01:00',
        },
        'end': {
            'dateTime': end_datetime,
            'timeZone': 'GMT+01:00',
        },
        'recurrence': ["RRULE:FREQ=DAILY;COUNT=1"],
        'attendees': attendees,
        'reminders': {
            'useDefault': True
            }
    }
    
    try:
        calendar_id = 'primary'
        event = service.events().insert(calendarId = calendar_id, body=event).execute()
        
        return Response({'message': 'Wydarzenie dodane do kalendarza.', 'event_id': event['id']}, status=201)
    except Exception as e:
        return Response({'error': f'Problem przy dodawaniu do kalendarza: {str(e)}'}, status=500)

@api_view(['GET'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
def get_google_events(request):
    credentials = check_for_credentials(request)
    if not credentials:
        return Response({'error': 'Brak ważnego tokenu. Przekierowywanie do autoryzacji.'}, status=401)
    
    service = build("calendar", "v3", credentials=credentials)
    now = datetime.datetime.now().isoformat() + "Z"
    print("Getting events")
    events_result = (
        service.events().list(
            calendarId="primary",
            timeMin=now,
            maxResults=10,
            singleEvents=True,
            orderBy="startTime",
        ).execute()
    )
    events = events_result.get("items", [])
    
    if not events:
        return JsonResponse({'message': 'Brak wydarzeń.'}, status=200)

    formatted_events = []
    for event in events:
        formatted_event = {
            'summary': event.get('summary', ''),
            'location': event.get('location', ''),
            'description': event.get('description', ''),
            'start_datetime': event['start'].get('dateTime', event['start'].get('date')),
            'end_datetime': event['end'].get('dateTime', event['end'].get('date')),
            'attendees': event.get('attendees', [])
        }
        formatted_events.append(formatted_event)

    return JsonResponse({'events': formatted_events}, json_dumps_params={'ensure_ascii': False},     status=200)

class UserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    
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