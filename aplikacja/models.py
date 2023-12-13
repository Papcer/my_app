from argon2.exceptions import VerifyMismatchError
from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager
from argon2 import PasswordHasher
from django.utils import timezone

class User(AbstractBaseUser):
    username = models.CharField(max_length=150, unique=True)
    password = models.CharField(max_length=150)
    last_login = models.DateTimeField(null=True, blank=True)

    USERNAME_FIELD = 'username'
    REQUIRED_FIELDS = []
    
    def __str__(self):
        return self.username

    def save(self, *args, **kwargs):
        super().save(*args, **kwargs)

    def set_password(self, raw_password):
        ph = PasswordHasher()
        self.password = ph.hash(raw_password)

    def check_password(self, raw_password):
        ph = PasswordHasher()
        try:
            ph.verify(self.password, raw_password)
            return True
        except VerifyMismatchError:
            return False

    @classmethod
    def create_user(cls, username, password=None):
        user = cls(username=username)
        user.set_password(password)
        user.save()
        return user

    
class Role(models.Model):
    role_name = models.CharField(max_length=255, unique=True)

class UserRoles(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    role = models.ForeignKey(Role, on_delete=models.CASCADE)

class Event(models.Model):
    title = models.CharField(max_length=255)
    description = models.TextField()
    start_date = models.DateTimeField()
    end_date = models.DateTimeField()
    attendees = models.CharField(max_length=255)
    city = models.CharField(max_length=255)
    zipcode = models.CharField(max_length=255)
    street = models.CharField(max_length=255)
    calendarID = models.CharField(max_length=255)
    
class Log(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    event = models.ForeignKey(Event, on_delete=models.SET_NULL, null=True, blank=True)
    log_type = models.CharField(max_length=255)
    log_description = models.TextField()
    timestamp = models.DateTimeField(default=timezone.now)

class UserData(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    name = models.CharField(max_length=255)
    surname = models.CharField(max_length=255)
    city = models.CharField(max_length=255)
    zipcode = models.CharField(max_length=10)
    street = models.CharField(max_length=255)

class PhoneNumbers(models.Model):
    phonenumber = models.CharField(max_length=11)

class UserContact(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    phonenumber = models.ForeignKey(PhoneNumbers, on_delete=models.CASCADE)

class UserLoginHistory(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    login_time = models.DateTimeField(default=timezone.now)
