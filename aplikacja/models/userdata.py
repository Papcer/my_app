from django.db import models
from users.models import User

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
    login_time = models.DateTimeField()