from django.conf import settings
from django.db import models
from django.utils import timezone
import uuid

class Post(models.Model):
    author = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    title = models.CharField(max_length=200)
    text = models.TextField()
    created_date = models.DateTimeField(default = timezone.now)
    uid = models.UUIDField(default=uuid.uuid4, unique=True)




    def __str__(self):
        return self.title   
