from django.db import models
from users.models import User

class Role(models.Model):
    role_name = models.CharField(max_length=255, unique=True)
    
class UserRoles(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    role = models.ForeignKey(Role, on_delete=models.CASCADE)