from django.db import models
from users.models import User
from events.models import Event

class Log(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    event = models.ForeignKey(Event, on_delete=models.CASCADE, null=True, blank=True)
    log_type = models.CharField(max_length=255)
    log_description = models.TextField()
    timestamp = models.DateTimeField()
