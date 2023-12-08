from django.db import models

class User(models.Model):
    username = models.CharField(max_length=150, uniqe=True)
    password = models.CharField(max_length=150)
    last_login = models.DateTimeField(null=True, blank=True)