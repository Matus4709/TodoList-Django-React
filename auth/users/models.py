from django.db import models
from django.contrib.auth.models import AbstractUser

class User(AbstractUser):
    name = models.CharField(max_length=255)
    email = models.EmailField(unique=True, max_length=255)
    password = models.CharField(max_length=255)
    username = None
    is_active = models.BooleanField(default=False)
    activation_key = models.CharField(max_length=40, blank=True)  # Klucz aktywacyjny
    key_expires = models.DateTimeField(null=True, blank=True)  # Data ważności klucza aktywacyjnego
    
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']

class Tasks(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='tasks')
    title = models.CharField(max_length=255)
    description = models.CharField(max_length=255, blank=True)
    completed = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField()

    def __str__(self):
        return self.title
    