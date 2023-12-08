import kwargs
from django.db import models
from django.db.models.signals import post_migrate
from django.dispatch import receiver

from .models import Role, User, UserRoles

@receiver(post_migrate)
def seed_data(sender, **kwargs):
    if kwargs.get['app_config'].name == 'aplikacja' and not Role.objects.exists():
        roles = ['admin', 'office_employee', 'customer_service_employee', 'marketing_team_employee', 'it_team_employee']
        for role_name in roles:
            Role.objects.create(role_name=role_name)
            
        users_data = [
            {'username': 'admin@epicup.pl', 'password': 'password', 'role': 'admin'},
            {'username': 'office_employee@epicup.pl', 'password': 'password', 'role': 'office_employee'},
            {'username': 'customer_service_employee@epicup.pl', 'password': 'password', 'role': 'customer_service_employee'},
            {'username': 'marketing_team_employee@epicup.pl', 'password': 'password', 'role': 'marketing_team_employee'},
            {'username': 'it_team_employee@epicup.pl', 'password': 'password', 'role': 'it_team_employee'}
        ]
        
        for user_data in users_data:
            user = User.objects.create(
                username=user_data['username'],
                password=user_data['password']
            )
            role = Role.objects.get(role_name=user_data['role'])
            UserRoles.objects.create(user=user, role=role)
