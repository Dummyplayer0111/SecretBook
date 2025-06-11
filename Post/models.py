from django.conf import settings
from django.db import models
from django.utils import timezone
import uuid

class Post(models.Model):
    author = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    title = models.CharField(max_length=200)
    text = models.TextField()
    created_date = models.DateTimeField(default = timezone.now)
    uuid = models.UUIDField(unique=True, null=True, blank=True, editable=False)

    def __str__(self):
        return self.title   
