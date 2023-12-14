from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi

from rest_framework.decorators import api_view, authentication_classes, permission_classes, schema
from rest_framework.permissions import IsAuthenticated, AllowAny
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from google.auth.transport.requests import Request
from rest_framework_simplejwt.authentication import JWTAuthentication
from django.http import JsonResponse
import json
from aplikacja.decorators import add_or_delete_permission, view_permission
from rest_framework.response import Response
from .models import Event, Log, UserData
from django.utils import timezone
from django.shortcuts import get_object_or_404
from django.db import transaction
import datetime

SCOPES = ['https://www.googleapis.com/auth/calendar.events']
TOKEN_FILE = 'aplikacja/token.json'

#zapis tokenu do pliku
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

@swagger_auto_schema(
    method='post',
    request_body=openapi.Schema(
        type=openapi.TYPE_OBJECT,
        properties={
            'title': openapi.Schema(type=openapi.TYPE_STRING, example='Nowe wydarzenie'),
            'description': openapi.Schema(type=openapi.TYPE_STRING,example='Opis wydarzenia'),
            'start_datetime': openapi.Schema(type=openapi.TYPE_STRING, format=openapi.FORMAT_DATETIME),
            'end_datetime': openapi.Schema(type=openapi.TYPE_STRING, format=openapi.FORMAT_DATETIME),
            'attendees': openapi.Schema(
                type=openapi.TYPE_ARRAY,
                items=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'email': openapi.Schema(type=openapi.TYPE_STRING, example='test@test.com'),
                    },
                    required=['email'],
                ),
                example=[
                    {"email": "test@test.com"},
                    {"email": "test2@example.com"}
                ]),
            'city': openapi.Schema(type=openapi.TYPE_STRING, example='Nowy Sącz'),
            'street': openapi.Schema(type=openapi.TYPE_STRING, example='Aleje Batorego'),
            'zipcode': openapi.Schema(type=openapi.TYPE_STRING,example='33-300'),
        },
        required=['title', 'description', 'start_datetime', 'end_datetime', 'attendees', 'city', 'street', 'zipcode'],
    ),
    responses={
        200: openapi.Response('Wydarzenie pomyślnie dodane'),
        400: openapi.Response('Bad Request'),
        401: openapi.Response('Użytkownik nie jest zautoryzowany'),
        500: openapi.Response('Internal Server Error'),
    },
)
@api_view(['POST'])
@authentication_classes([JWTAuthentication])
@add_or_delete_permission
@permission_classes([IsAuthenticated])
def save_google_calendar(request):
    """
    Api, które pozwala zapisać wydarzenie w kalendarzu
    """
    title = request.data.get('title')
    description = request.data.get('description')
    start_datetime = request.data.get('start_datetime')
    end_datetime = request.data.get('end_datetime')
    attendees = [attendee['email'] for attendee in request.data.get('attendees', [])]
    city = request.data.get('city')
    street = request.data.get('street')
    zipcode = request.data.get('zipcode')
    location = f"{street} {zipcode} {city}"

    if not title or not description or not start_datetime or not end_datetime or not attendees or not location:
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
        'attendees': [{'email': email} for email in attendees],
        'reminders': {
            'useDefault': True
        }
    }
    try:
        calendar_id = 'primary'
        event = service.events().insert(calendarId=calendar_id, body=event).execute()

        event_db = Event.objects.create(
            title=title,
            description=description,
            start_date=start_datetime,
            end_date=end_datetime,
            attendees=attendees,
            city=city,
            zipcode=zipcode,
            street=street,
            calendarID=event['id']
        )

        log = Log.objects.create(
            log_type='Dodanie wydarzenia',
            log_description=f"Dodano wydarzenie o nazwie '{title}'",
            timestamp=timezone.now() + timezone.timedelta(hours=1),
            event_id=event_db.id,
            user=request.user,
        )


        return Response({'message': 'Wydarzenie dodane do kalendarza.', 'event_link': event['htmlLink'] , 'event_id': event['id']}, status=201)
    except Exception as e:
        return Response({'error': f'Problem przy dodawaniu do kalendarza: {str(e)}'}, status=500)

@swagger_auto_schema(
    method='get',
    responses={
        200: openapi.Response('Wydarzenia zostały pomyślnie wczytane'),
        400: openapi.Response('Bad Request'),
        401: openapi.Response('Użytkownik nie jest zautoryzowany'),
        500: openapi.Response('Internal Server Error'),
    },
)
@api_view(['GET'])
@authentication_classes([JWTAuthentication])
@view_permission
@permission_classes([IsAuthenticated])
def get_google_events(request):
    """
    Api, które pozwala na pobranie wszystkich eventów
    Zwracane obiekty:
        event: wszystkie obiektu eventów zawierające wszystkie informację
    """
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
            'id': event.get('id', ''),
            'summary': event.get('summary', ''),
            'location': event.get('location', ''),
            'description': event.get('description', ''),
            'start_datetime': event['start'].get('dateTime', event['start'].get('date')),
            'end_datetime': event['end'].get('dateTime', event['end'].get('date')),
            'attendees': event.get('attendees', [])
        }
        formatted_events.append(formatted_event)

    return JsonResponse({'events': formatted_events}, json_dumps_params={'ensure_ascii': False},     status=200)

@swagger_auto_schema(
    method='get',
    responses={
        200: openapi.Response('Wydarzenie zostało pomyslnie wczytane'),
        400: openapi.Response('Bad Request'),
        401: openapi.Response('Użytkownik nie jest zautoryzowany'),
        500: openapi.Response('Internal Server Error'),
    },
)
@api_view(['GET'])
@authentication_classes([JWTAuthentication])
@view_permission
@permission_classes([IsAuthenticated])
def get_single_google_event(request, event_id):
    """
    Api, które pozwala na pobranie istniejącego eventu po podaniu id
    Wymagane paramtry:
        -event_id: wskazuje na dany event

    Zwracane obiekty:
        event: obiekt eventu zawierający wszystkie dane
    """
    credentials = check_for_credentials(request)
    if not credentials:
        return JsonResponse({'error': 'Brak ważnego tokenu. Przekierowywanie do autoryzacji.'}, status=401)
    
    service = build("calendar", "v3", credentials=credentials)
    
    try:
        event = service.events().get(calendarId="primary", eventId=event_id).execute()
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)
    
    formatted_event = {
        'id': event.get('id', ''),
        'summary': event.get('summary', ''),
        'location': event.get('location', ''),
        'description': event.get('description', ''),
        'start_datetime': event['start'].get('dateTime', event['start'].get('date')),
        'end_datetime': event['end'].get('dateTime', event['end'].get('date')),
        'attendees': event.get('attendees', [])
    }
    
    return JsonResponse({'event': formatted_event}, json_dumps_params={'ensure_ascii': False}, status=200)


@swagger_auto_schema(
    method='delete',
    responses={
        200: openapi.Response('Wydarzenie zostało usunięte'),
        400: openapi.Response('Bad Request'),
        401: openapi.Response('Użytkownik nie jest zautoryzowany'),
        500: openapi.Response('Internal Server Error'),
    },
)
@api_view(['DELETE'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
def delete_event(request, event_id):
    """
    Api, które pozwala na usunięcie istniejącego eventu
    Wymagane paramtry:
        -event_id: wskazuje na dany event
    """

    credentials = check_for_credentials(request)
    if not credentials:
        return Response({'error': 'Brak ważnego tokenu. Przekierowywanie do autoryzacji.'}, status=401)

    service = build("calendar", "v3", credentials=credentials)

    try:
        service.events().delete(calendarId='primary', eventId=event_id).execute()

        #usuwanie z bazy danych -> w bazie jako klucz bedzie null poniewaz usunieto wpis z tabeli Events
        event_db = get_object_or_404(Event, calendarID=event_id)
        event_db.delete()

        #dodaj log
        log = Log.objects.create(
            log_type='Usunięcie wydarzenia',
            log_description=f"Usunięto wydarzenie o id = '{event_id}'",
            timestamp=timezone.now() + timezone.timedelta(hours=1),
            event_id=event_db.id,
            user=request.user,
        )


        return Response({'message': 'Wydarzenie zostało usunięte z kalendarza.'}, status=201)
    except Exception as e:
        return Response({'error': f'Problem przy usuwaniu danych z kalendarza: {str(e)}'}, status=500)


@swagger_auto_schema(
    method='put',
    request_body=openapi.Schema(
        type=openapi.TYPE_OBJECT,
        properties={
            'title': openapi.Schema(type=openapi.TYPE_STRING, example='Nowe wydarzenie'),
            'description': openapi.Schema(type=openapi.TYPE_STRING,example='Opis wydarzenia'),
            'start_datetime': openapi.Schema(type=openapi.TYPE_STRING, format=openapi.FORMAT_DATETIME),
            'end_datetime': openapi.Schema(type=openapi.TYPE_STRING, format=openapi.FORMAT_DATETIME),
            'attendees': openapi.Schema(
                type=openapi.TYPE_ARRAY,
                items=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'email': openapi.Schema(type=openapi.TYPE_STRING, example='test@test.com'),
                    },
                    required=['email'],
                ),
                example=[
                    {"email": "test@test.com"},
                    {"email": "test2@example.com"}
                ]),
            'city': openapi.Schema(type=openapi.TYPE_STRING, example='Nowy Sącz'),
            'street': openapi.Schema(type=openapi.TYPE_STRING, example='Aleje Batorego'),
            'zipcode': openapi.Schema(type=openapi.TYPE_STRING, example='33-300'),
        },
        required=['title', 'description', 'start_datetime', 'end_datetime', 'attendees', 'city', 'street', 'zipcode'],
    ),
    responses={
        200: openapi.Response('Wydarzenie pomyślnie dodane'),
        400: openapi.Response('Bad Request'),
        401: openapi.Response('Użytkownik nie jest zautoryzowany'),
        500: openapi.Response('Internal Server Error'),
    },
)
@api_view(['PUT'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
def edit_event(request, event_id):
    """
    Api, które pozwala na edytowanie istniejącego eventu
    Wymagane paramtry:
        -event_id: wskazuje na dany event
    """
    title = request.data.get('title')
    description = request.data.get('description')
    start_datetime = request.data.get('start_datetime')
    end_datetime = request.data.get('end_datetime')
    attendees = request.data.get('attendees')
    city = request.data.get('city')
    street = request.data.get('street')
    zipcode = request.data.get('zipcode')
    location = f"{street} {zipcode} {city}"

    if not title or not description or not start_datetime or not end_datetime or not attendees or not location:
        return Response({'error': 'Wszystkie pola wymagane'}, status=400)

    credentials = check_for_credentials(request)
    if not credentials:
        return Response({'error': 'Brak ważnego tokenu. Przekierowywanie do autoryzacji.'}, status=401)

    service = build("calendar", "v3", credentials=credentials)
    try:
        event = service.events().get(calendarId='primary', eventId=event_id).execute()
        old_title = event['summary']

        event['summary'] = title
        event['location'] = location
        event['description'] = description
        event['start']['dateTime'] = start_datetime
        event['end']['dateTime'] = end_datetime
        event['attendees'] = attendees

        with transaction.atomic():
            #zmien dane w tabeli event
            event_db = get_object_or_404(Event, calendarID=event_id)
            event_db.title = title
            event_db.description = description
            event_db.start_date = start_datetime
            event_db.end_date = end_datetime
            event_db.attendees = attendees
            event_db.city = city
            event_db.zipcode = zipcode
            event_db.street = street

            event_db.save()

            #dodaje logi
            event_id_db = Event.objects.filter(calendarID=event_id).first()
            log = Log.objects.create(
                log_type='Aktualizacja wydarzenia',
                log_description=f"Zaktualizowano wydarzenie '{old_title}'",
                timestamp=timezone.now() + timezone.timedelta(hours=1),
                event_id= event_id_db.id if event else None,
                user=request.user,
            )

        updated_event = service.events().update(calendarId='primary', eventId=event_id, body=event).execute()

        return Response({'message': 'Wydarzenie zostalo zaktualizowane.'}, status=200)
    except Exception as e:
        return Response({'error': f'Problem przy aktualizacji wydarzenia: {str(e)}'}, status=500)